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


def vendor_fixture(entries):
    page = 4096
    compressed = ramdisk.compress(archive(entries))
    dtb, bootconfig = b'test-dtb', b'test-config'
    header = bytearray(page)
    header[:8] = b'VNDRBOOT'
    struct.pack_into('<II', header, 8, 4, page)
    struct.pack_into('<I', header, 24, len(compressed))
    struct.pack_into('<II', header, 2096, 2128, len(dtb))
    struct.pack_into('<IIII', header, 2112, 108, 1, 108, len(bootconfig))
    table = struct.pack('<III', len(compressed), 0, 1) + b'\0' * 96
    return bytes(header) + b''.join(d + b'\0' * ((-len(d)) % page) for d in [compressed, dtb, table, bootconfig])


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

    def test_profile_identity_is_stable_across_windows_text_newlines(self):
        p = kit.profile('muyu-os4.0.3.0')
        original = kit.public_file
        parent = kit.ROOT / '.local/test-temp'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as tmp:
            cert = Path(tmp) / 'public.pem'
            self.assertTrue(cert.resolve().is_relative_to(parent.resolve()))
            cert.write_bytes(original(p['stock_certificate']).read_text(encoding='utf-8').replace('\n', '\r\n').encode())
            expected = kit.profile_digest(p)
            with patch.object(kit, 'public_file', side_effect=lambda name: cert if name == p['stock_certificate'] else original(name)):
                self.assertEqual(kit.profile_digest(p), expected)

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

    def test_matching_module_does_not_require_a_fake_content_change(self):
        vendor = vendor_fixture([('lib/modules/cifs.ko', b'already matching')])
        self.assertEqual(kit.verify_vendor_contents(vendor, vendor, {'lib/modules/cifs.ko': b'already matching'}), [])
        with self.assertRaises(ValueError):
            kit.verify_vendor_contents(vendor, vendor, {'lib/modules/missing.ko': b'data'})

    def test_public_export_excludes_private_baselines(self):
        from tools import export_project
        (kit.ROOT / '.local/test-temp').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=kit.ROOT / '.local/test-temp') as tmp:
            root = Path(tmp)
            self.assertTrue(root.resolve().is_relative_to((kit.ROOT / '.local/test-temp').resolve()))
            (root / '.local').mkdir()
            (root / '.local/device-backup.img').write_bytes(b'private baseline')
            (root / 'README.md').write_text('public source', encoding='utf-8')
            with patch.object(export_project, 'ROOT', root):
                self.assertEqual(list(export_project.public_files()), [('README.md', 'public source')])
                key_marker = '-----BEGIN ' + 'PRIVATE KEY-----'
                (root / 'README.md').write_text(key_marker, encoding='utf-8')
                with self.assertRaises(ValueError):
                    list(export_project.public_files())

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
