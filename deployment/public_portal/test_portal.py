"""Offline regression checks; never write synthetic events to the business database."""
import json
from pathlib import Path
import tempfile
import unittest

from deployment.public_portal.observe_access import normalize, read_batch
from deployment.public_portal.render import render


def record(**fields):
    item = dict(request_id='a' * 32, time='1792468800.5', ip='192.0.2.1',
                host='example.invalid', port=80, method='GET', path='/',
                status=200, bytes=42, duration='0.001', ua='offline-unit-test')
    item.update(fields)
    return item


def encoded(**fields):
    return (json.dumps(record(**fields)) + '\n').encode()


class PortalTests(unittest.TestCase):
    def test_partial_line_is_not_checkpointed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            line = encoded()
            path.write_bytes(line + line[:20])
            key, offset, rows = read_batch(path, {})
            self.assertEqual(offset, len(line))
            self.assertEqual(len(rows), 1)
            with path.open('ab') as stream:
                stream.write(line[20:])
            _, new_offset, rows = read_batch(path, {key: offset})
            self.assertEqual(new_offset, len(line) * 2)
            self.assertEqual(len(rows), 1)

    def test_replay_has_stable_event_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_bytes(encoded())
            key, offset, rows = read_batch(path, {})
            self.assertEqual(read_batch(path, {})[2], rows)
            self.assertEqual(read_batch(path, {key: offset})[2], [])

    def test_rotation_preserves_old_inode_and_reads_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            rotated = Path(directory) / 'access.log.1'
            path.write_bytes(encoded())
            key, offset, _ = read_batch(path, {})
            path.rename(rotated)
            path.write_bytes(encoded(request_id='b' * 32))
            state = {key: offset}
            self.assertEqual(read_batch(rotated, state)[2], [])
            new_key, _, rows = read_batch(path, state)
            self.assertNotEqual(new_key, key)
            self.assertEqual(rows[0][0], 'b' * 32)

    def test_truncated_file_is_read_from_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_bytes(encoded() * 2)
            key, offset, _ = read_batch(path, {})
            path.write_bytes(encoded(request_id='b' * 32))
            self.assertEqual(read_batch(path, {key: offset})[2][0][0], 'b' * 32)

    def test_malformed_line_does_not_block_following_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_bytes(b'not-json\n' + encoded())
            with self.assertLogs(level='WARNING'):
                _, offset, rows = read_batch(path, {})
            self.assertEqual(offset, path.stat().st_size)
            self.assertEqual(len(rows), 1)

    def test_download_is_an_observation_not_a_file_open(self):
        row = normalize(record(path='/downloads/1?token=never-store-this'))
        self.assertEqual(row[6], '/downloads/1')
        self.assertEqual(row[11], 'file_download_request')
        self.assertEqual(normalize(record(path='/static/img/logo-test.png'))[11],
                         'file_callback_request')

    def test_untrusted_inputs_are_validated(self):
        with self.assertRaises(ValueError):
            normalize(record(ip='not-an-ip'))
        with self.assertRaises(ValueError):
            normalize(record(request_id='invalid'))
        self.assertEqual(normalize(record(diagnostic='token=secret'))[12], '')

    def test_rendered_catalog_is_static_and_escaped(self):
        page = render([{'id': 17, 'name': '<script>alert(1)</script>.docx'}])
        self.assertIn('href="/downloads/17"', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('<script>alert(1)</script>', page)


if __name__ == '__main__':
    unittest.main()
