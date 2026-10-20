"""Read-only verification of saved current-architecture diagnostic checkpoints."""
import argparse
import hashlib
import json
from pathlib import Path

import torch


def verify(directory):
    root = Path(directory)
    study = json.loads((root/'results.json').read_text(encoding='utf-8'))
    expected = {(r['test_scenario'],r['seed']):r for r in study['runs']}
    files = list(root.glob('fold_*/seed_*/result.json'))
    if len(files) != len(expected) or len(expected) != len(study['config']['seeds'])*study['config']['folds']:
        raise ValueError('missing or duplicate run artifacts')
    seen, dimensions, updates = set(), set(), []
    for path in files:
        row = json.loads(path.read_text(encoding='utf-8'))
        key = (row['test_scenario'],row['seed'])
        if key in seen or key not in expected or row['optimizer_steps'] <= 0:
            raise ValueError('invalid saved training run')
        seen.add(key)
        checkpoint = path.with_name('current_198_unconstrained_ablation.pt')
        digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        if digest != row['checkpoint_sha256'] or digest != expected[key]['checkpoint_sha256']:
            raise ValueError('checkpoint hash mismatch')
        state = torch.load(checkpoint,map_location='cpu',weights_only=True)
        dimensions.add(int(state['q_net.net.0.weight'].shape[1]))
        updates.append(row['optimizer_steps'])
    if dimensions != {198}:
        raise ValueError('unexpected/legacy checkpoint architecture')
    return {'verified_checkpoints':len(files),'input_dimensions':sorted(dimensions),
            'minimum_optimizer_updates':min(updates),'release_allowed':study['release_gate']['allowed']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',default='experiments/results/ait_mechanism_20261020')
    print(json.dumps(verify(p.parse_args().directory)))
