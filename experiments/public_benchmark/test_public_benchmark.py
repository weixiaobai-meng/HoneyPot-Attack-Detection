"""Synthetic unit fixtures only; these files never become experimental samples."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock
import io

import torch

from step3_dqn_pruning.graph_loader import causal_graph_to_pyg
from .prepare import category, label_index, match_truth, normalize, line_key
from .run import preflight, load
from .range_zip import RangeReader


class PublicBenchmarkTests(unittest.TestCase):
    def test_unknown_truth_is_not_normal(self):
        self.assertIsNone(match_truth({},'auth',['unknown']))
        index = {('auth',line_key('known')):{'value':0,'labels':[],'member':'sample','line':1}}
        self.assertEqual(match_truth(index,'auth',['known'])['attack_event'],0)
        self.assertIsNone(match_truth(index,'auth',['known','unseen']))

    def test_audit_aggregate_requires_all_source_lines(self):
        rows = ['type=SYSCALL value=one','type=EXECVE value=two']
        index = {('audit',line_key(row)):{'value':i,'labels':['attack'] if i else [],'member':'sample','line':i+1}
                 for i,row in enumerate(rows)}
        self.assertEqual(match_truth(index,'audit',[' '.join(rows)])['attack_event'],1)
        del index[('audit',line_key(rows[0]))]
        self.assertIsNone(match_truth(index,'audit',[' '.join(rows)]))

    def test_ambiguous_duplicate_lines_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root/'labels/intranet_server/logs/auth.log'
            raw = root/'gather/intranet_server/logs/auth.log'
            labels.parent.mkdir(parents=True); raw.parent.mkdir(parents=True)
            labels.write_text(json.dumps({'line':2,'labels':['attack']})+'\n')
            raw.write_text('duplicate\nduplicate\nnormal\n')
            index, counts = label_index(root)
            self.assertIsNone(match_truth(index,'auth',['duplicate']))
            self.assertEqual(match_truth(index,'auth',['normal'])['attack_event'],0)
            self.assertEqual(counts['auth_attack'],1)

    def test_labels_not_consumed_by_normalizer(self):
        row = {'@timestamp':'2022-01-01T00:00:00Z','full_log':'192.0.2.1 - sample',
               'data':{'srcip':'192.0.2.1','url':'/'},'rule':{'id':'1','level':5}}
        before = normalize(row,'wazuh','example','access','host')
        row.update({'label':1,'scenario_role':'attack','ground_truth':'secret_answer'})
        self.assertEqual(before,normalize(row,'wazuh','example','access','host'))

    def test_source_scope_does_not_include_other_web_servers(self):
        self.assertIsNone(category('/var/log/apache2/proxy-access-access.log'))
        self.assertEqual(category('/var/log/apache2/intranet-access.log'),'access')

    def test_linear_path_has_no_deletion_but_redundant_graph_does(self):
        graph = {'nodes':[{'id':x,'type':'event'} for x in 'abc'],
                 'edges':[{'edge_id':'ab','source':'a','target':'b','edge_kind':'correlation'},
                          {'edge_id':'bc','source':'b','target':'c','edge_kind':'correlation'}],
                 'required_paths':[{'source':'a','target':'c'}]}
        row = {'id':'unit','group':'unit','nodes':3,'edges':2,'event_count':0,'attack_event_count':0}
        self.assertTrue(preflight([(row,causal_graph_to_pyg(graph))])['zero_feasible_deletions'])
        graph['edges'].append({'edge_id':'ac','source':'a','target':'c','edge_kind':'correlation'})
        row['edges'] = 3
        self.assertFalse(preflight([(row,causal_graph_to_pyg(graph))])['zero_feasible_deletions'])

    def test_range_reader_rejects_unpinned_host(self):
        with self.assertRaises(ValueError):
            RangeReader('https://example.com/file.zip',100)

    def test_range_reader_refuses_full_response(self):
        reader = RangeReader('https://zenodo.org/records/1/files/test.zip',100)
        self.addCleanup(reader.close)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.headers = {'Content-Length':'100'}
        reader.session.get = MagicMock(return_value=response)
        with self.assertRaisesRegex(ValueError,'did not honor byte range'):
            reader.read(1)
        response.raw.read.assert_not_called()

    def test_range_reader_enforces_budget_and_reuses_cache(self):
        reader = RangeReader('https://zenodo.org/records/1/files/test.zip',100,max_transfer=100)
        self.addCleanup(reader.close)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 206
        response.headers = {'Content-Range':'bytes 0-99/100'}
        response.raw = io.BytesIO(bytes(range(100)))
        reader.session.get = MagicMock(return_value=response)
        self.assertEqual(reader.read(2),b'\x00\x01')
        reader.seek(50)
        self.assertEqual(reader.read(1),b'\x32')
        self.assertEqual(reader.session.get.call_count,1)
        self.assertEqual(reader.transferred,100)
        reader.cache.clear()
        with self.assertRaisesRegex(ValueError,'budget exhausted'):
            reader.read(1)

    def test_duplicate_source_events_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = {'nodes':[{'id':'a','type':'process'},{'id':'b','type':'file'}],
                     'edges':[{'edge_id':'e','source':'a','target':'b','source_event_ids':['source:1']}]}
            truth = {'source:1':{'attack_event':1}}
            for name,data in [('graph.json',graph),('truth.json',truth),('targets.json',{'e':1})]:
                (root/name).write_text(json.dumps(data))
            row = {'id':'test_window','group':'a','graph':'graph.json','event_truth':'truth.json','targets':'targets.json',
                   'graph_sha256':hashlib.sha256((root/'graph.json').read_bytes()).hexdigest(),
                   'targets_sha256':hashlib.sha256((root/'targets.json').read_bytes()).hexdigest()}
            manifest = {'protocol':'ait_publisher_event_proxy_v1','graphs':[row,dict(row,group='b')]}
            (root/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'source events reused'):
                load(root/'manifest.json')


if __name__ == '__main__':
    unittest.main()
