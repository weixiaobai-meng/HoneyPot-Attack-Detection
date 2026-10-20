"""Preflight and bounded current-architecture DQN pilot; never auto-promote weights."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import random
import subprocess
import time

import numpy as np
import torch

from experiments.baselines import evidence_rule_actions, random_matched_actions
from step3_dqn_pruning.constraints import EvidencePathGuard
from step3_dqn_pruning.graph_loader import causal_graph_to_pyg, EDGE_FEATURE_NAMES
from step3_dqn_pruning.trainer import DQNTrainer, pruning_metrics_from_actions
from .prepare import SCENARIOS, write_json


def hash_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(manifest):
    root = manifest.parent
    info = json.loads(manifest.read_text(encoding='utf-8'))
    if info['protocol'] != 'ait_publisher_event_proxy_v1':
        raise ValueError('unexpected public protocol')
    items, seen = [], set()
    for row in info['graphs']:
        if hash_file(root/row['graph']) != row['graph_sha256'] or hash_file(root/row['targets']) != row['targets_sha256']:
            raise ValueError('prepared artifact hash mismatch')
        source = json.loads((root/row['graph']).read_text(encoding='utf-8'))
        truth = json.loads((root/row['event_truth']).read_text(encoding='utf-8'))
        targets = json.loads((root/row['targets']).read_text(encoding='utf-8'))
        if seen & set(truth):
            raise ValueError('source events reused between prepared windows')
        seen.update(truth)
        if any(edge.get('scenario_role') or edge.get('scenario_id') or edge.get('campaign_id') for edge in source['edges']):
            raise ValueError('experimental answers leaked into graph')
        expected = {e['edge_id']:int(all(truth[i]['attack_event'] for i in e['source_event_ids'])) for e in source['edges']}
        if targets != expected:
            raise ValueError('proxy targets disagree with publisher event truth mapping')
        graph = causal_graph_to_pyg(source)
        graph.y = torch.tensor([targets[e['edge_id']] for e in source['edges']],dtype=torch.long)
        graph.scenario_id = row['group']
        graph.window_id = row['id']
        items.append((row, graph))
    return info, items


def preflight(items):
    rows = []
    for row, graph in items:
        mask = torch.ones(len(graph.edges_info),dtype=torch.bool)
        reasons = Counter()
        for index in range(len(graph.edges_info)):
            # Removing other edges cannot create a missing path. Zero legal
            # single-edge removals therefore proves zero feasible compression.
            reason = EvidencePathGuard(graph).rejection_reason(mask,index)
            reasons[reason or 'legal_deletion'] += 1
        rows.append({'window':row['id'],'scenario':row['group'],'nodes':row['nodes'],'edges':row['edges'],
                     'events':row['event_count'],'attack_events':row['attack_event_count'],
                     'association_edges':row['edges']-row['event_count'],'action_space':dict(reasons)})
    counts = Counter()
    for row in rows:
        counts.update(row['action_space'])
    return {'windows':rows,'totals':dict(counts),'independent_scenarios':len({r['scenario'] for r in rows}),
            'zero_feasible_deletions':counts['legal_deletion']==0,
            'note':'Reachability constraints are modeled structure, not independent attack-path truth.'}


def evaluate(items, trainer, seed):
    rows = []
    for row, graph in items:
        inputs = graph.clone()
        del inputs.y  # Test answers cannot be consumed by inference.
        start = time.perf_counter()
        actions, details = trainer.predict_actions(inputs, decision_batch_size=1)
        milliseconds = (time.perf_counter()-start)*1000
        # A second, tampered-label pass must be identical.
        inputs.y = 1-graph.y
        checked,_ = trainer.predict_actions(inputs, decision_batch_size=1)
        if not torch.equal(actions,checked):
            raise ValueError('prediction changed when test labels changed')
        rule,_ = EvidencePathGuard(graph).filter_actions(evidence_rule_actions(graph))
        random_actions,_ = EvidencePathGuard(graph).filter_actions(random_matched_actions(
            graph,int((actions==1).sum()),seed))
        methods = {'keep_all':torch.zeros_like(actions),'evidence_rule_same_constraints':rule,
                   'random_matched_same_constraints':random_actions,'dqn_current_198':actions}
        for method, proposed in methods.items():
            metrics = pruning_metrics_from_actions(proposed,graph.y)
            association = torch.tensor([e.get('edge_kind')=='correlation' for e in graph.edges_info],dtype=torch.bool)
            proxy = pruning_metrics_from_actions(proposed[association],graph.y[association])
            rows.append({'window':row['id'],'scenario':row['group'],'method':method,
                'edges':len(proposed),'pruned_edges':int((proposed==1).sum()),
                'association_count':int(association.sum()),'association_pruned':int(((proposed==1)&association).sum()),
                'association_proxy_noise_f1':proxy['noise_f1'] if bool(association.any()) else None,
                'independent_causal_path_recall':None,
                'compression_ratio':metrics['compression_ratio'],
                'audit':EvidencePathGuard(graph).metrics(proposed),
                'dqn_forward_passes':details['model_forward_passes'] if method=='dqn_current_198' else None,
                'dqn_raw_pruned':int((details['raw_actions']==1).sum()) if method=='dqn_current_198' else None,
                'inference_ms':milliseconds if method=='dqn_current_198' else None})
    return rows


def run(args):
    torch.set_num_threads(1)
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError('use a new output directory; experiment results are append-only')
    output.mkdir(parents=True)
    manifest = Path(args.manifest).resolve()
    info, items = load(manifest)
    audit = preflight(items)
    write_json(output/'preflight.json',audit)
    print(json.dumps({'preflight':audit['totals'],'zero_feasible_deletions':audit['zero_feasible_deletions']}),flush=True)
    groups = sorted({r['group'] for r,g in items})
    if groups != SCENARIOS:
        raise ValueError('all eight publisher scenarios required')
    test_group, validation_group = groups[0], groups[1]
    train = [g for r,g in items if r['group'] not in (test_group,validation_group)]
    validation = [g for r,g in items if r['group']==validation_group]
    test = [(r,g) for r,g in items if r['group']==test_group]
    options = {'epochs':args.epochs,'patience':args.epochs,'seed':args.seed,'device':'cpu',
               'use_path_constraints':True,'batch_size':4,'min_replay_size':16,'train_frequency':16,
               'target_update_steps':20,'replay_capacity':4000}
    write_json(output/'frozen_run_config.json',{'train_groups':groups[2:],'validation_group':validation_group,
        'test_group':test_group,'options':options,'manifest_sha256':hash_file(manifest),
        'purpose':'bounded_feasibility_pilot_not_formal_full_benchmark',
        'feature_names':EDGE_FEATURE_NAMES,'checkpoint_input_dim':198})
    trainer = DQNTrainer(**options)
    before = {k:v.detach().cpu().clone() for k,v in trainer.model.state_dict().items()}
    start = time.perf_counter()
    checkpoint = output/'current_198_pilot.pt'
    trainer.train(train,validation,save_path=str(checkpoint))
    train_seconds = time.perf_counter()-start
    state = torch.load(checkpoint,map_location='cpu',weights_only=True)
    assert state['q_net.net.0.weight'].shape[1] == 198
    changed = sum(not torch.equal(before[k],v) for k,v in state.items())
    assert trainer.optimizer_steps > 0 and changed > 0, 'no real parameter update occurred'
    rows = evaluate(test,trainer,args.seed)
    result = {'status':'pilot_completed_not_release_eligible','model_architecture':'evidence_dynamic_198',
        'checkpoint_sha256':hash_file(checkpoint),'training_seconds':train_seconds,
        'optimizer_steps':trainer.optimizer_steps,'environment_steps':trainer.global_step,
        'changed_state_tensors':changed,'epochs_completed':len(trainer.training_history),
        'preflight':{k:v for k,v in audit.items() if k!='windows'},
        'held_out_test_scenario':test_group,'validation_scenario':validation_group,
        'training_scenarios':groups[2:],'seed':args.seed,'test_label_invariance_verified':True,
        'training_history':trainer.training_history,'test_results':rows,
        'release_gate':{'allowed':False,'reasons':['independent_association_or_path_truth_missing',
            'full_grouped_multiseed_and_external_domain_validation_incomplete'] +
            (['no_feasible_pruning_under_current_graph_and_constraints'] if audit['zero_feasible_deletions'] else [])},
        'provenance':{'manifest_sha256':hash_file(manifest),'python':platform.python_version(),
            'torch':torch.__version__,'git_revision':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),
            'source_sha256':{str(p):hash_file(p) for p in [Path(__file__),Path('step3_dqn_pruning/trainer.py'),
                Path('step3_dqn_pruning/model.py'),Path('step3_dqn_pruning/constraints.py'),Path('step2_causal_graph/graph_builder.py')]}}}
    write_json(output/'results.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('training_history','test_results','provenance','preflight')},ensure_ascii=False),flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',default='experiments/data/public/ait_prepared_v1/manifest.json')
    p.add_argument('--output',default='experiments/results/ait_public_pilot_20261020')
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--epochs',type=int,default=3)
    run(p.parse_args())
