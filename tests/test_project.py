import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import yaml

from kernelkit import project as kit, ramdisk


def archive(entries):
    result = bytearray()
    for i, (name, data) in enumerate([*entries, ('TRAILER!!!', b'')]):
        name = name.encode() + b'\0'
        fields = [i + 1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        result += b'070701' + ''.join(f'{n:08x}' for n in fields).encode() + name
        result += b'\0' * ((-len(result)) % 4)
        result += data + b'\0' * ((-len(data)) % 4)
    result += b'\0' * ((-len(result)) % 512)
    return bytes(result)


class ProjectChecks(unittest.TestCase):
    def test_profile_refuses_path_traversal(self):
        for name in ['../elsewhere', '/absolute', 'x/y', 'A-B']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                kit.profile(name)

    def test_profile_pins_source_and_certificate(self):
        p = kit.profile('muyu-os4.0.3.0')
        self.assertEqual(p['required_config']['MODULE_SIG_PROTECT'], 'y')
        modified = copy.deepcopy(p)
        modified['common_commit'] = 'main'
        with patch.object(kit, 'read_json', return_value=modified), self.assertRaises(ValueError):
            kit.profile(p['id'])
        modified = copy.deepcopy(p)
        modified['stock_certificate_der_sha256'] = '0' * 64
        with patch.object(kit, 'read_json', return_value=modified), self.assertRaises(ValueError):
            kit.profile(p['id'])

    def test_firmware_change_alters_artifact_identity(self):
        p = kit.profile('muyu-os4.0.3.0')
        q = copy.deepcopy(p)
        q['firmware'] = 'another-version'
        self.assertNotEqual(kit.profile_digest(p), kit.profile_digest(q))

    def test_cpio_replacement_preserves_other_files_and_metadata(self):
        old = archive([('lib/modules/cifs.ko', b'old'), ('lib/modules/modules.load', b'cifs.ko\n')])
        new, changed = ramdisk.rewrite(old, {'lib/modules/cifs.ko': b'longer replacement'})
        self.assertEqual(changed, ['lib/modules/cifs.ko'])
        before, after = list(ramdisk.entries(old)), list(ramdisk.entries(new))
        self.assertEqual(after[1]['raw'], before[1]['raw'])
        self.assertEqual(after[0]['content'], b'longer replacement')
        self.assertEqual(after[0]['fields'][:6], before[0]['fields'][:6])
        self.assertEqual(ramdisk.decompress(ramdisk.compress(new)), new)

    def test_missing_replacement_is_detectable(self):
        old = archive([('lib/modules/other.ko', b'old')])
        new, changed = ramdisk.rewrite(old, {'lib/modules/cifs.ko': b'replacement'})
        self.assertEqual(new, old)
        self.assertEqual(changed, [])

    def test_private_baseline_tampering_is_rejected(self):
        p = kit.profile('muyu-os4.0.3.0')
        temp_parent = (kit.ROOT / '.local/test-temp').resolve()
        temp_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_parent) as tmp:
            path = Path(tmp)
            self.assertTrue(path.resolve().is_relative_to(temp_parent))
            (path / 'boot.img').write_bytes(b'changed')
            kit.write_json(path / 'baseline.json', {'device': p['device'], 'firmware': p['firmware'], 'files': {'boot.img': '0' * 64}})
            with patch.object(kit, 'baseline_dir', return_value=path), self.assertRaises(ValueError):
                kit.validate_baseline(p)

    def test_workflows_and_private_data_boundaries(self):
        for file in (kit.ROOT / '.github/workflows').glob('*.yaml'):
            workflow = yaml.load(file.read_text(), Loader=yaml.BaseLoader)
            self.assertEqual(workflow['permissions']['contents'], 'read')
            for job in workflow['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:
                        self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
                    if 'upload-artifact@' in step.get('uses', ''):
                        self.assertNotIn('.local/', step['with']['path'])
        ignore = (kit.ROOT / '.gitignore').read_text()
        self.assertIn('.local/', ignore)
        self.assertIn('signing_key.pem', ignore)


if __name__ == '__main__':
    unittest.main()
