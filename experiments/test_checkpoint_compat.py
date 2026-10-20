"""Inference regression tests only; generated fixtures are not experiment data."""
import json
from pathlib import Path
import tempfile
import unittest

import torch
from step3_dqn_pruning.checkpoint import load_inference_checkpoint
from step3_dqn_pruning.graph_loader import NUM_EDGE_FEATURES
from step3_dqn_pruning.model import DynamicEdgeQNetwork


class CheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        torch.set_num_threads(1)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'policy.pt'

    def save_model(self, *, legacy=False):
        model = DynamicEdgeQNetwork(edge_attr_dim=0 if legacy else NUM_EDGE_FEATURES,
                                    state_feature_dim=0 if legacy else 2)
        torch.save(model.state_dict(), self.path)
        return model

    def test_legacy_requires_opt_in_and_preserves_every_weight(self):
        model = self.save_model(legacy=True)
        with self.assertRaises(ValueError):
            load_inference_checkpoint(self.path)
        trainer, meta = load_inference_checkpoint(self.path, allow_legacy=True)
        self.assertEqual(meta['mode'], 'legacy_dqn_checkpoint')
        self.assertEqual(meta['edge_feature_dim'], 0)
        self.assertFalse(meta['dynamic_state_observed'])
        self.assertFalse(meta['formal_evaluation_ready'])
        for key, value in model.state_dict().items():
            self.assertTrue(torch.equal(value, trainer.model.state_dict()[key]))

    def test_current_model_remains_current(self):
        self.save_model()
        trainer, meta = load_inference_checkpoint(self.path)
        self.assertEqual(meta['mode'], 'dqn_checkpoint')
        self.assertEqual(meta['checkpoint_input_dim'], 198)
        self.assertTrue(trainer.use_dynamic_state)

    def test_unknown_dimension_is_rejected(self):
        model = self.save_model(legacy=True)
        state = model.state_dict()
        state['q_net.net.0.weight'] = torch.zeros(256, 129)
        torch.save(state, self.path)
        with self.assertRaises(ValueError):
            load_inference_checkpoint(self.path, allow_legacy=True)

    def test_missing_weight_is_not_silently_initialized(self):
        model = self.save_model(legacy=True)
        state = model.state_dict()
        del state['q_net.net.0.bias']
        torch.save(state, self.path)
        with self.assertRaises(RuntimeError):
            load_inference_checkpoint(self.path, allow_legacy=True)

    def test_raw_model_decisions_are_separate_from_constraints(self):
        model = self.save_model(legacy=True)
        # Controlled unit fixture that always proposes prune; not a production model.
        with torch.no_grad():
            for parameter in model.parameters():
                parameter.zero_()
            model.q_net.net[-1].bias[1] = 1
        torch.save(model.state_dict(), self.path)
        trainer, _ = load_inference_checkpoint(self.path, allow_legacy=True)
        graph_path = self.path.with_suffix('.json')
        graph = {'nodes':[{'id':'a','type':'network'},{'id':'b','type':'file'}],
                 'edges':[{'edge_id':'e1','source':'a','target':'b','action':'file_access',
                           'relation_type':'subject_action_object','edge_kind':'event',
                           'source_event_ids':['u1'],'evidence_basis':['observed_event']}],
                 'required_paths':[]}
        graph_path.write_text(json.dumps(graph),encoding='utf-8')
        result = trainer.predict_and_prune(str(graph_path),str(self.path.with_name('pruned.json')))
        stats = result['pruning_stats']
        self.assertTrue(stats['model_inference_executed'])
        self.assertEqual(stats['model_forward_passes'],1)
        self.assertEqual(stats['model_raw_pruned_edges'],1)
        self.assertEqual(stats['model_raw_pruned_edges'] - stats['constraint_restored_edges'], stats['pruned_edges'])
        self.assertEqual(stats['original_edges'],stats['kept_edges']+stats['pruned_edges'])


if __name__ == '__main__':
    unittest.main()
