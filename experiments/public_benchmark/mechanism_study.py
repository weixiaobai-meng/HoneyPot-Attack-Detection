"""Grouped diagnostic ablation: learned actions vs direct-evidence/path constraints.

All checkpoints are current 198-input models. This is an offline mechanism study,
not authorization to relax production evidence constraints.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import copy
import json
from pathlib import Path
import random
import time

import numpy as np
import torch

from experiments.baselines import evidence_rule_actions, random_matched_actions
from experiments.run_benchmark import _bootstrap_mean_ci
from step3_dqn_pruning.constraints import EvidencePathGuard
from step3_dqn_pruning.trainer import DQNTrainer, pruning_metrics_from_actions
from .prepare import SCENARIOS, write_json
from .run import load, hash_file


def metrics(graph, actions):
    event_mask = torch.tensor([e['edge_kind']=='event' for e in graph.edges_info],dtype=torch.bool)
    association = ~event_mask
    truth = graph.y
    attack_event_mask = event_mask & (truth==1)
    normal_event_mask = event_mask & (truth==0)
    proxy = pruning_metrics_from_actions(actions[association],truth[association])
    guard = EvidencePathGuard(graph).metrics(actions)
    return {'edges':len(actions),'deleted':int((actions==1).sum()),
            'observed_events':int(event_mask.sum()),'observed_events_deleted':int(((actions==1)&event_mask).sum()),
            'attack_events':int(attack_event_mask.sum()),'attack_events_deleted':int(((actions==1)&attack_event_mask).sum()),
            'normal_events':int(normal_event_mask.sum()),'normal_events_deleted':int(((actions==1)&normal_event_mask).sum()),
            'associations':int(association.sum()),'associations_deleted':int(((actions==1)&association).sum()),
            'proxy_cpr':int(proxy['cpr']),'proxy_wpc':int(proxy['wpc']),
            'proxy_wkr':int(proxy['wkr']),'proxy_ckc':int(proxy['ckc']),
            'required_paths':guard['required_path_count'],'required_paths_kept':guard['required_paths_kept']}


def summary(rows):
    summed = {k:sum(r[k] for r in rows) for k in rows[0] if k not in ('latency_ms',)}
    summed.update({
        'compression':summed['deleted']/max(1,summed['edges']),
        'observed_retention':1-summed['observed_events_deleted']/max(1,summed['observed_events']),
        'attack_event_retention':1-summed['attack_events_deleted']/max(1,summed['attack_events']),
        'normal_event_filter':summed['normal_events_deleted']/max(1,summed['normal_events']),
        'association_compression':summed['associations_deleted']/max(1,summed['associations']),
        'association_proxy_noise_f1':2*summed['proxy_cpr']/max(1,2*summed['proxy_cpr']+summed['proxy_wpc']+summed['proxy_wkr']),
        'modeled_path_retention':summed['required_paths_kept']/max(1,summed['required_paths']),
        'inference_ms':sum(r.get('latency_ms',0) for r in rows)})
    return summed


def worker(job):
    manifest, out_root, fold, seed, epochs = job
    torch.set_num_threads(1)
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    _, items = load(Path(manifest))
    test_group = SCENARIOS[fold]
    val_group = SCENARIOS[(fold+1)%len(SCENARIOS)]
    train = [g for r,g in items if r['group'] not in (test_group,val_group)]
    val = [g for r,g in items if r['group']==val_group]
    test = [(r,g) for r,g in items if r['group']==test_group]
    destination = Path(out_root)/f'fold_{fold}'/f'seed_{seed}'
    destination.mkdir(parents=True,exist_ok=False)
    trainer = DQNTrainer(epochs=epochs,patience=5,seed=seed,device='cpu',use_path_constraints=False,
        batch_size=4,min_replay_size=16,train_frequency=16,target_update_steps=20,replay_capacity=4000)
    started = time.perf_counter()
    checkpoint = destination/'current_198_unconstrained_ablation.pt'
    trainer.train(train,val,save_path=str(checkpoint))
    by_method = {}
    for row, graph in test:
        blind = graph.clone(); del blind.y
        begin = time.perf_counter()
        proposed, details = trainer.predict_actions(blind,decision_batch_size=1)
        elapsed = (time.perf_counter()-begin)*1000
        complete_guarded,_ = EvidencePathGuard(graph).filter_actions(proposed)
        evidence_graph = graph.clone(); evidence_graph.required_paths = []
        evidence_only,_ = EvidencePathGuard(evidence_graph).filter_actions(proposed)
        rule = evidence_rule_actions(graph)
        rule_guarded,_ = EvidencePathGuard(graph).filter_actions(rule)
        rule_evidence,_ = EvidencePathGuard(evidence_graph).filter_actions(rule)
        random_raw = random_matched_actions(graph,int((proposed==1).sum()),seed)
        random_guarded,_ = EvidencePathGuard(graph).filter_actions(random_raw)
        methods = {'keep_all':torch.zeros_like(proposed),'evidence_rule':rule,
            'rule_full_guard':rule_guarded,'rule_direct_evidence_only':rule_evidence,
            'dqn_no_guard':proposed,'dqn_full_guard':complete_guarded,'dqn_direct_evidence_only':evidence_only,
            'random_matched_raw':random_raw,'random_matched_full_guard':random_guarded}
        for method, actions in methods.items():
            result = metrics(graph,actions)
            if method.startswith('dqn_'):
                result['latency_ms'] = elapsed
            by_method.setdefault(method,[]).append(result)
    result = {'test_scenario':test_group,'validation_scenario':val_group,'seed':seed,
        'training_seconds':time.perf_counter()-started,'optimizer_steps':trainer.optimizer_steps,
        'epochs_completed':len(trainer.training_history),'checkpoint_sha256':hash_file(checkpoint),
        'checkpoint_input_dim':198,'formal_evaluation_ready':False,'release_allowed':False,
        'training_history':trainer.training_history,'methods':{k:summary(v) for k,v in by_method.items()}}
    write_json(destination/'result.json',result)
    return {k:v for k,v in result.items() if k!='training_history'}


def main(args):
    root = Path(args.output).resolve()
    if root.exists():
        raise ValueError('use a fresh output directory')
    root.mkdir(parents=True)
    manifest = Path(args.manifest).resolve()
    seeds = [int(x) for x in args.seeds.split(',')]
    config = {'manifest_sha256':hash_file(manifest),'seeds':seeds,'epochs_max':args.epochs,
        'folds':len(SCENARIOS),'early_stop_validation_only':True,
        'purpose':'post_preflight_mechanism_diagnosis_not_confirmatory_study',
        'association_labels':'publisher_event_derived_relevance_proxy_not_causal_truth',
        'release_allowed':False,'source_sha256':hash_file(Path(__file__))}
    write_json(root/'frozen_config.json',config)
    jobs = [(str(manifest),str(root),fold,seed,args.epochs) for fold in range(len(SCENARIOS)) for seed in seeds]
    results = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(worker,job) for job in jobs]
        for completed in as_completed(futures):
            result = completed.result()
            results.append(result)
            print(json.dumps({'completed':len(results),'total':len(jobs),'scenario':result['test_scenario'],
                'seed':result['seed'],'epochs':result['epochs_completed'],
                'dqn_no_guard_compression':result['methods']['dqn_no_guard']['compression'],
                'dqn_full_guard_compression':result['methods']['dqn_full_guard']['compression']}),flush=True)
    aggregate = {}
    for method in results[0]['methods']:
        aggregate[method] = {}
        for metric in ('compression','attack_event_retention','observed_retention','normal_event_filter',
                       'association_compression','association_proxy_noise_f1','modeled_path_retention','inference_ms'):
            values = []
            for scenario in SCENARIOS:
                group = [r['methods'][method][metric] for r in results if r['test_scenario']==scenario]
                values.append(sum(group)/len(group))
            aggregate[method][metric] = {'mean':sum(values)/len(values),'scenario_bootstrap_ci95':_bootstrap_mean_ci(values),
                                         'scenario_means':dict(zip(SCENARIOS,values))}
    write_json(root/'results.json', {'config':config,'runs':sorted(results,key=lambda r:(r['test_scenario'],r['seed'])),
        'aggregate':aggregate,'independent_scenario_count':8,'causal_path_recall':None,
        'release_gate':{'allowed':False,'reasons':['official_event_labels_do_not_certify_association_paths',
            'diagnostic_guard_relaxation_is_not_a_production_change','external_domain_validation_not_completed']}})
    print('GROUPED_MECHANISM_STUDY_COMPLETE',flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',default='experiments/data/public/ait_prepared_v1/manifest.json')
    p.add_argument('--output',default='experiments/results/ait_mechanism_20261020')
    p.add_argument('--seeds',default='42,43,44,45,46')
    p.add_argument('--epochs',type=int,default=12)
    p.add_argument('--workers',type=int,default=4)
    main(p.parse_args())
