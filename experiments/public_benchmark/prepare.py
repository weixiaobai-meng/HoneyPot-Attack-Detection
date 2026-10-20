"""Map AIT alerts to exact publisher-annotated log lines; build label-blind graphs.

Event truth is publisher-derived. Association targets are explicitly a relevance
proxy, NOT independently verified causal edges. Unknown matches are excluded.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import zipfile

import requests
import yaml

from step2_causal_graph import CausalGraphBuilder

SCENARIOS = ['fox','harrison','russellmitchell','santos','shaw','wardbeck','wheeler','wilson']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def category(path):
    if 'audit/audit.log' in path:
        return 'audit'
    if '/auth.log' in path:
        return 'auth'
    if 'intranet' in path and '-access.log' in path:
        return 'access'
    if 'intranet' in path and '-error.log' in path:
        return 'error'
    return None


def line_key(text):
    return hashlib.sha256(text.strip().encode()).digest()


def label_index(root):
    index = {}
    inventory = Counter()
    for label_file in sorted((root/'labels/intranet_server/logs').rglob('*')):
        if not label_file.is_file():
            continue
        relative = label_file.relative_to(root).as_posix()
        kind = category(relative)
        if not kind:
            continue
        annotations = {}
        for line in label_file.read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            annotations[int(row['line'])] = row['labels']
        raw_relative = relative.replace('labels/', 'gather/', 1)
        with (root/raw_relative).open(encoding='utf-8') as stream:
            for number, line in enumerate(stream, 1):
                labels = annotations.get(number, [])
                # Publisher LDSv2 definition: other lines in these paired,
                # simulation-trimmed files are normal. Not applied to other logs.
                value = int(bool(labels))
                key = (kind, line_key(line))
                entry = {'value':value, 'labels':labels, 'member':raw_relative, 'line':number}
                if key in index:
                    previous = index[key]
                    if previous is None or previous['value'] != value or previous['labels'] != labels:
                        index[key] = None  # Ambiguous duplicate text is never guessed.
                else:
                    index[key] = entry
                inventory[kind + ('_attack' if value else '_normal')] += 1
        if annotations and max(annotations) > number:
            raise ValueError('publisher annotation line lies outside paired log')
    return index, dict(inventory)


def match_truth(index, kind, raw_lines):
    matched = []
    for text in raw_lines:
        fragments = re.split(r'\s+(?=type=[A-Z_]+\s)',text.strip()) if kind == 'audit' else [text]
        for fragment in fragments:
            entry = index.get((kind, line_key(fragment)))
            if entry is None:
                return None
            matched.append(entry)
    if not matched:
        return None
    return {'attack_event':int(any(x['value'] for x in matched)), 'references':matched}


def normalize(row, sensor, event_id, kind, hostname):
    if sensor == 'wazuh':
        ts = datetime.fromisoformat(row['@timestamp'].replace('Z','+00:00'))
        raw = row.get('full_log','')
        info = row.get('data') or {}
        rule = str(row.get('rule',{}).get('id',''))
        level = int(row.get('rule',{}).get('level',0))
        remote = info.get('srcip')
    else:
        ts = datetime.fromtimestamp(float(row['LogData']['Timestamps'][0]), timezone.utc)
        raw = '\n'.join(row['LogData']['RawLogData'])
        info = {}
        rule = str(row.get('AnalysisComponent',{}).get('AnalysisComponentType',''))
        level, remote = 0, None
    if not remote:
        candidate = re.search(r'^(\d{1,3}(?:\.\d{1,3}){3})\s|\[client (\d{1,3}(?:\.\d{1,3}){3})',raw)
        remote = next((g for g in candidate.groups() if g),None) if candidate else None
    pid = re.search(r'\bpid=(\d+)',raw)
    username = info.get('srcuser') or info.get('dstuser')
    source_type = 'network' if remote else ('process' if pid else 'service')
    source_id = f'ip:{remote}' if remote else f'{hostname}:{source_type}:{pid.group(1) if pid else kind}'
    action = 'connect' if kind in ('access','error') else 'unknown'
    if kind == 'auth' and 'sshd' in raw:
        action = 'ssh_login'
    if kind == 'audit':
        syscall = re.search(r'\bsyscall=(\d+)',raw)
        action = {'0':'read','1':'write','2':'openat','59':'execve','257':'openat','56':'fork','42':'connect'}.get(syscall.group(1),'unknown') if syscall else 'unknown'
    path = info.get('url') or kind
    event = {'event_id':event_id, 'event_type':'audit', 'timestamp':ts.astimezone(timezone.utc).isoformat(),
             'action':action, 'source':{'type':source_type,'id':source_id,'label':source_id,'ip':remote},
             'object':{'type':'url' if kind in ('access','error') else 'service',
                       'id':f'{hostname}:{path}','label':str(path),'host':hostname,'path':str(path)},
             'confidence':0.8, 'severity':'high' if level >= 10 else 'medium' if level >= 5 else 'low',
             'evidence':{'publisher_sensor':sensor,'log_category':kind,'detector_rule_id':rule},
             'raw_details':{'username':username} if username else {}}
    return event, (sensor,kind,rule)


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')


def prepare_scenario(scenario, ads, lds, output, max_events=48):
    index, label_counts = label_index(lds/scenario)
    config_path = lds/scenario/'publisher_server_config.yaml'
    if not config_path.exists():
        response = requests.get(f'https://raw.githubusercontent.com/ait-aecid/alert-data-set/main/server_configs/{scenario}.yaml',timeout=(15,30))
        response.raise_for_status()
        config_path.write_bytes(response.content)
    configs = yaml.safe_load(config_path.read_text())
    intranet_ip = str(configs['intranet_server']['default_ipv4_address'])
    windows, stats, all_rows = {}, Counter(), 0
    with zipfile.ZipFile(ads/'ait_ads.zip') as archive:
        for sensor in ('wazuh','aminer'):
            member = f'{scenario}_{sensor}.json'
            with archive.open(member) as stream:
                for line_number, line in enumerate(stream,1):
                    row = json.loads(line)
                    all_rows += 1
                    if sensor == 'wazuh':
                        location = row.get('location','')
                        host_ip = str(row.get('agent',{}).get('ip',''))
                        raw_lines = [row.get('full_log','')]
                    else:
                        locations = row.get('LogData',{}).get('LogResources',[])
                        if len(set(locations)) != 1:
                            stats['unsupported_resource_list'] += 1
                            continue
                        location = locations[0]
                        host_ip = str(row.get('AMiner',{}).get('ID',''))
                        raw_lines = row.get('LogData',{}).get('RawLogData',[])
                    kind = category(location)
                    if host_ip != intranet_ip or kind is None:
                        stats['outside_selected_sources'] += 1
                        continue
                    truth = match_truth(index,kind,raw_lines)
                    if truth is None:
                        stats['unmatched_or_ambiguous'] += 1
                        continue
                    event_id = f'ait:{scenario}:{sensor}:{line_number}'
                    event, signature = normalize(row,sensor,event_id,kind,'intranet_server')
                    ts = datetime.fromisoformat(event['timestamp']).timestamp()
                    bucket = int(ts//600)
                    window = windows.setdefault(bucket, {'signatures':set(),'events':{},'count':0})
                    window['count'] += 1
                    window['signatures'].add(signature)
                    # Deterministic label-blind reservoir; preserve diverse
                    # sensor/rule/time/source combinations before repeated scans.
                    sample_key = (signature,event['source']['id'],int(ts//30))
                    rank = sha(event_id.encode())
                    current = window['events'].get(sample_key)
                    if current is None or rank < current[0]:
                        window['events'][sample_key] = (rank,event,truth)
                    if len(window['events']) > max_events * 2:
                        keep = sorted(window['events'],key=lambda k:window['events'][k][0])[:max_events]
                        window['events'] = {k:window['events'][k] for k in keep}
                    stats['matched_attack' if truth['attack_event'] else 'matched_normal'] += 1
    buckets = sorted(windows)
    if not buckets:
        raise ValueError(f'{scenario}: no exact publisher log matches')
    diverse = sorted(buckets,key=lambda b:(-len(windows[b]['signatures']),-windows[b]['count'],b))[:4]
    uniform = [buckets[round(i*(len(buckets)-1)/3)] for i in range(4)]
    selected = sorted(set(diverse + uniform))
    rows = []
    for bucket in selected:
        samples = sorted(windows[bucket]['events'].values(),key=lambda x:x[0])[:max_events]
        events = sorted([x[1] for x in samples],key=lambda e:(e['timestamp'],e['event_id']))
        truths = {x[1]['event_id']:x[2] for x in samples}
        graph = CausalGraphBuilder(include_experiment_annotations=False).build_from_alerts(events)
        targets = {edge['edge_id']: int(all(truths[e]['attack_event'] for e in edge['source_event_ids'])) for edge in graph['edges']}
        graph_id = f'{scenario}_{bucket}'
        folder = output/scenario/str(bucket)
        write_json(folder/'graph.json',graph)
        write_json(folder/'events.json',events)
        write_json(folder/'event_truth.json',truths)
        write_json(folder/'association_proxy_targets.json',targets)
        rows.append({'id':graph_id,'group':scenario,'graph':str((folder/'graph.json').relative_to(output)),
                     'events':str((folder/'events.json').relative_to(output)),
                     'event_truth':str((folder/'event_truth.json').relative_to(output)),
                     'targets':str((folder/'association_proxy_targets.json').relative_to(output)),
                     'nodes':len(graph['nodes']),'edges':len(graph['edges']),
                     'event_count':len(events),'attack_event_count':sum(x['attack_event'] for x in truths.values()),
                     'graph_sha256':sha((folder/'graph.json').read_bytes()),
                     'targets_sha256':sha((folder/'association_proxy_targets.json').read_bytes())})
    result = {'scenario':scenario,'all_alert_rows':all_rows,'coverage':dict(stats),
              'source_label_counts':label_counts,'selected_windows':len(rows),'available_windows':len(windows),
              'selected_events':sum(r['event_count'] for r in rows),'selected_attack_events':sum(r['attack_event_count'] for r in rows),
              'server_config_sha256':sha(config_path.read_bytes()),'graphs':rows}
    write_json(output/scenario/'inventory.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('graphs','source_label_counts')}),flush=True)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ads',default='experiments/data/public/ait_ads')
    p.add_argument('--lds',default='experiments/data/public/ait_ldsv2_selected')
    p.add_argument('--output',default='experiments/data/public/ait_prepared_v1')
    p.add_argument('--scenario',action='append')
    args = p.parse_args()
    output = Path(args.output).resolve()
    if (output/'manifest.json').exists():
        raise ValueError('manifest already exists; use a new output version to preserve results')
    inventories = [prepare_scenario(s,Path(args.ads),Path(args.lds),output) for s in args.scenario or SCENARIOS]
    write_json(output/'manifest.json', {'protocol':'ait_publisher_event_proxy_v1','formal_evaluation_ready':False,
        'label_scope':'official_event_truth_with_derived_association_relevance_proxy_not_causal_gold',
        'sampling':'10min_windows_top4_observed_signature_diversity_plus4_uniform_max48_hash_reservoir',
        'scenarios':inventories,'graphs':[r for x in inventories for r in x['graphs']]})
