"""Versioned kernel build profiles and fail-closed local image packaging."""
from __future__ import annotations

import gzip
import itertools
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import elf, ramdisk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'third_party'))
import avbtool


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def public_file(name):
    path = (ROOT / name).resolve()
    require(path.is_relative_to(ROOT) and '.local' not in path.relative_to(ROOT).parts, 'Invalid public project path')
    require(path.is_file(), f'Missing project file: {name}')
    return path


def profile(profile_id):
    require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,79}', profile_id), 'Invalid profile ID')
    path = ROOT / 'profiles' / (profile_id + '.json')
    p = read_json(path)
    require(p['schema_version'] == 1 and p['id'] == profile_id, 'Unsupported or mismatched profile')
    for key in ['common_commit', 'manifest_commit', 'repo_commit']:
        require(re.fullmatch('[0-9a-f]{40}', p[key]), f'{key} must be an immutable commit SHA')
    require(p['manifest_url'] == 'https://android.googlesource.com/kernel/manifest', 'Unsupported source origin')
    require(p['device'] == 'muyu', 'This project currently supports muyu only')
    for name in [p['fragment'], p['stock_certificate'], p['protected_exports'], *p['patches']]:
        public_file(name)
    cert = x509.load_pem_x509_certificate(public_file(p['stock_certificate']).read_bytes())
    require(cert.fingerprint(hashes.SHA256()).hex() == p['stock_certificate_der_sha256'], 'Stock public certificate hash mismatch')
    for part in ['boot', 'vendor_boot', 'init_boot']:
        require(re.fullmatch('[0-9a-f]{64}', p['baseline_images'][part]), f'Missing baseline hash: {part}')
    require(len(p['modules']) == 4 and len({Path(n).name for n in p['modules']}) == 4, 'Expected four distinct replacement modules')
    for name in p['modules']:
        require(not name.startswith('/') and '..' not in Path(name).parts and name.endswith('.ko'), 'Unsafe module path')
    return p


def profile_digest(p):
    files = [p['fragment'], p['stock_certificate'], p['protected_exports'], *p['patches']]
    # All profile inputs here are UTF-8 text; ignore platform newline encoding.
    # Binary artifact and original image hashes remain byte-for-byte checks.
    value = {'profile': p, 'inputs': {n: sha(public_file(n).read_text(encoding='utf-8').encode('utf-8')) for n in files}}
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def run(args, cwd=None, capture=False):
    result = subprocess.run([str(a) for a in args], cwd=cwd, check=True, capture_output=capture)
    return result.stdout.decode('utf-8') if capture else None


def kernel_from_boot(b):
    require(b[:8] == b'ANDROID!' and struct.unpack_from('<I', b, 40)[0] == 4, 'Expected boot v4')
    require(struct.unpack_from('<I', b, 12)[0] == 0 and struct.unpack_from('<I', b, 1580)[0] == 0, 'Unsupported ramdisk or boot signature layout')
    size = struct.unpack_from('<I', b, 8)[0]
    kernel = b[4096:4096 + size]
    require(len(kernel) == size and kernel[56:60] == b'ARM\x64', 'Expected uncompressed ARM64 Image')
    return kernel


def scan_boot_certificates(b):
    """Discover valid X509 DER objects actually present in the original kernel."""
    kernel = kernel_from_boot(b)
    certs = {}
    pos = 0
    while True:
        pos = kernel.find(b'\x30\x82', pos)
        if pos < 0:
            break
        size = int.from_bytes(kernel[pos + 2:pos + 4], 'big') + 4
        if 512 <= size <= 16384:
            try:
                cert = x509.load_der_x509_certificate(kernel[pos:pos + size])
                certs[cert.fingerprint(hashes.SHA256()).hex()] = cert
            except ValueError:
                pass
        pos += 2
    require(certs, 'No original kernel certificates found; do not guess a replacement trust key')
    return list(certs.values())


def read_avb(b, partition):
    footer = avbtool.AvbFooter(b[-avbtool.AvbFooter.SIZE:])
    start = footer.vbmeta_offset
    header = avbtool.AvbVBMetaHeader(b[start:start + avbtool.AvbVBMetaHeader.SIZE])
    off = start + header.SIZE + header.authentication_data_block_size + header.descriptors_offset
    descriptors = avbtool.parse_descriptors(b[off:off + header.descriptors_size])
    hashes_ = [d for d in descriptors if isinstance(d, avbtool.AvbHashDescriptor)]
    require(len(hashes_) == 1 and hashes_[0].partition_name == partition, 'Unexpected AVB partition descriptor')
    require(all(isinstance(d, (avbtool.AvbHashDescriptor, avbtool.AvbPropertyDescriptor)) for d in descriptors), 'Unsupported AVB descriptor; manual review required')
    d = hashes_[0]
    require(d.flags in (0, 1), 'Unsupported hash descriptor flags')
    return dict(partition_size=len(b), rollback_index=header.rollback_index,
                rollback_index_location=header.rollback_index_location, flags=header.flags,
                hash_algorithm=d.hash_algorithm, salt=d.salt.hex(), hash_flags=d.flags,
                properties={d.key: d.value.decode('utf-8') for d in descriptors if isinstance(d, avbtool.AvbPropertyDescriptor)})


def module_archives(paths):
    for path in paths:
        with tarfile.open(path) as archive:
            for member in archive:
                if member.isfile() and member.name.endswith('.ko'):
                    require(not member.name.startswith('/') and '..' not in Path(member.name).parts, 'Unsafe archive module path')
                    yield member.name, archive.extractfile(member).read()


def early_modules(boot, vendor):
    size = struct.unpack_from('<I', boot, 12)[0]
    for name, fragments in [('init_boot', [boot[4096:4096 + size]]), ('vendor_boot', ramdisk.parts(vendor)[3])]:
        for fragment in fragments:
            if fragment:
                for entry in ramdisk.entries(ramdisk.decompress(fragment)):
                    if entry['name'].endswith('.ko'):
                        yield name + '/' + entry['name'], entry['content']


def baseline_dir(p):
    return ROOT / '.local' / 'baselines' / p['id']


def import_baseline(p, boot, vendor_boot, init_boot, modules_tar):
    dest = baseline_dir(p)
    require(not dest.exists(), f'Baseline already exists: {dest}; use a new profile instead of overwriting')
    images = {part: Path(path) for part, path in [('boot', boot), ('vendor_boot', vendor_boot), ('init_boot', init_boot)]}
    for part, path in images.items():
        require(sha(path.read_bytes()) == p['baseline_images'][part], f'Original {part} does not match this firmware profile')
    certs = scan_boot_certificates(images['boot'].read_bytes())
    require(any(c.fingerprint(hashes.SHA256()).hex() == p['stock_certificate_der_sha256'] for c in certs), 'Original kernel does not contain pinned stock certificate')
    records = []
    for name, data in itertools.chain(module_archives([modules_tar]), early_modules(images['init_boot'].read_bytes(), images['vendor_boot'].read_bytes())):
        m = elf.module(data, name)
        m['signature'] = elf.verify_signature(data, certs)
        records.append(m)
    require(records and len({m['path'] for m in records}) == len(records), 'Empty or duplicate module paths in baseline')
    replacements = {'vendor_boot/lib/modules/' + Path(n).name for n in p['modules']}
    require(replacements <= {m['path'] for m in records}, 'Missing replacement modules in original vendor_boot')
    for part, path in images.items():
        read_avb(path.read_bytes(), part)
    # All checks above complete before the private baseline is created.
    dest.mkdir(parents=True)
    for part, path in images.items():
        shutil.copyfile(path, dest / (part + '.img'))
    shutil.copyfile(modules_tar, dest / 'stock-modules.tar')
    write_json(dest / 'modules.json', records)
    write_json(dest / 'baseline.json', {
        'profile_digest': profile_digest(p), 'device': p['device'], 'firmware': p['firmware'],
        'files': {n.name: sha(n.read_bytes()) for n in dest.iterdir() if n.is_file()},
    })
    print('Original images and module baseline imported locally:', dest)
    return dest


def validate_baseline(p):
    directory = baseline_dir(p)
    b = read_json(directory / 'baseline.json')
    require(b['device'] == p['device'] and b['firmware'] == p['firmware'], 'Baseline identity mismatch')
    for name, expected in b['files'].items():
        require(Path(name).name == name, 'Unsafe baseline file name')
        require(sha((directory / name).read_bytes()) == expected, f'Private baseline changed: {name}')
    for part, expected in p['baseline_images'].items():
        require(sha((directory / (part + '.img')).read_bytes()) == expected, f'Profile baseline hash mismatch: {part}')
    return directory, read_json(directory / 'modules.json')


def artifact_dist(directory):
    directory = Path(directory).resolve()
    return directory / 'dist' if (directory / 'dist' / 'Image').is_file() else directory


def verify_build(p, directory, require_provenance=True):
    dist = artifact_dist(directory)
    records = dist.parent / 'build-record'
    if require_provenance:
        provenance = read_json(records / 'provenance.json')
        require(provenance['profile_digest'] == profile_digest(p), 'Artifact was built from a different profile or patch set')
        require(provenance['common_commit'] == p['common_commit'] and provenance['manifest_commit'] == p['manifest_commit'], 'Source pin mismatch')
        for name, digest in read_json(records / 'artifact-hashes.json').items():
            require(Path(name).name == name and sha((dist / name).read_bytes()) == digest, f'Artifact hash mismatch: {name}')
    kernel = (dist / 'Image').read_bytes()
    require(kernel[56:60] == b'ARM\x64', 'Invalid ARM64 kernel Image')
    marker = kernel.index(b'IKCFG_ST\x1f\x8b\x08') + 8
    import zlib
    config = zlib.decompress(kernel[marker:], 31).decode()
    require(config == (dist / '.config').read_text(encoding='utf-8'), 'Embedded and exported kernel configuration differ')
    entries = dict(line.split('=', 1) for line in config.splitlines() if line.startswith('CONFIG_') and '=' in line)
    for name, value in p['required_config'].items():
        require(entries.get('CONFIG_' + name) == value, 'Missing required configuration: ' + name)
    for name in p['forbidden_config']:
        require(entries.get('CONFIG_' + name) != 'y', 'Forbidden ABI/security configuration: ' + name)
    certs, certdata = elf.image_certificate_list(dist / 'Image', dist / 'System.map')
    stock = x509.load_pem_x509_certificate(public_file(p['stock_certificate']).read_bytes())
    require(stock.public_bytes(serialization.Encoding.DER) in certdata, 'Original public certificate missing from new kernel trust list')
    symbols = {}
    for line in (dist / 'kernel_aarch64_Module.symvers').read_text().splitlines():
        fields = line.split()
        require(len(fields) >= 3, 'Malformed Module.symvers')
        symbols[fields[1]] = {'crc': int(fields[0], 16), 'provider': fields[2]}
    protected = set(public_file(p['protected_exports']).read_text().split())
    modules = []
    for name in p['modules']:
        data = (dist / Path(name).name).read_bytes()
        m = elf.module(data, 'vendor_boot/lib/modules/' + Path(name).name)
        require(m['versions'], 'Replacement module has no version table: ' + name)
        m['signature'] = elf.verify_signature(data, certs)
        if Path(name).stem != 'dns_resolver':
            require(len(m['signature']) == 64, 'CIFS module signature must verify against a kernel certificate')
        elif m['signature'] == 'unsigned':
            require(m['info'].get('depends') == [''], 'Unsigned DNS module unexpectedly depends on another module')
            require(all(symbols.get(s, {}).get('provider') == 'vmlinux' for s in set(m['versions']) | set(m['imports'])), 'Unsigned DNS module imports a module-owned symbol')
            require(not set(m['exports']) & protected, 'Unsigned DNS module exports a protected symbol')
        else:
            require(len(m['signature']) == 64, 'Untrusted DNS module signature')
        for symbol, crc in m['versions'].items():
            require(symbol in symbols and symbols[symbol]['crc'] == crc, f'New module CRC mismatch: {name}: {symbol}')
        modules.append(m)
    cifs = next(m for m in modules if m['path'].endswith('/cifs.ko'))
    require(set(cifs['info']['depends'][0].split(',')) == {'cifs_arc4', 'cifs_md4', 'dns_resolver'}, 'Unexpected CIFS dependency set')
    return {'dist': dist, 'certs': certs, 'symbols': symbols, 'modules': modules,
            'config_sha256': sha(config.encode()), 'kernel_sha256': sha(kernel)}


def verify_compatibility(p, directory, require_provenance=True):
    verified = verify_build(p, directory, require_provenance)
    baseline, stock = validate_baseline(p)
    replacements = {m['path']: m for m in verified['modules']}
    modules = [m for m in stock if m['path'] not in replacements] + list(replacements.values())
    stock_exports = {s for m in modules for s in m['exports']}
    problems, warnings = [], []
    flags = verified['modules'][0]['info']['vermagic'][0].split(' ', 1)[1]
    allowed_unversioned = set(p.get('allowed_unversioned_modules', []))
    for m in modules:
        if not m['versions']:
            require(m['path'] in allowed_unversioned, 'Unrecognized module without CRC table: ' + m['path'])
            warnings.append('No version table; runtime verification required: ' + m['path'])
        else:
            magic = m['info'].get('vermagic', [''])[0].split(' ', 1)
            require(len(magic) == 2 and magic[1] == flags, 'Module configuration/vermagic flags differ: ' + m['path'])
        for symbol, crc in m['versions'].items():
            target = verified['symbols'].get(symbol)
            if target and target['crc'] != crc:
                problems.append({'module': m['path'], 'symbol': symbol, 'expected': hex(crc), 'actual': hex(target['crc'])})
            elif not target and symbol not in stock_exports:
                problems.append({'module': m['path'], 'symbol': symbol, 'missing': True})
    original_certs = scan_boot_certificates((baseline / 'boot.img').read_bytes())
    trusted_original = {c.fingerprint(hashes.SHA256()).hex() for c in original_certs}
    trusted_new = {c.fingerprint(hashes.SHA256()).hex() for c in verified['certs']}
    for m in stock:
        if m['path'] not in replacements and m['signature'] in trusted_original:
            require(m['signature'] in trusted_new, 'Original module trust certificate was removed')
    unknown = [m['path'] for m in stock if m['signature'].startswith('unrecognized-signer:')]
    if unknown:
        warnings.append(f'{len(unknown)} original files already have an unrecognized signer; retained unchanged')
    report = {'profile': p['id'], 'firmware': p['firmware'], 'profile_digest': profile_digest(p),
              'module_files': len(modules), 'problems': problems, 'warnings': warnings,
              'replacements': verified['modules'], 'kernel_sha256': verified['kernel_sha256'],
              'device_tested': False, 'artifact_provenance_verified': require_provenance}
    require(not problems, 'Module ABI incompatibility:\n' + json.dumps(problems[:20], indent=2))
    return verified, baseline, report


def prepare_sources(p, kernel):
    kernel = Path(kernel).resolve()
    common = kernel / 'common'
    require(run(['git', 'rev-parse', 'HEAD'], common, True).strip() == p['common_commit'], 'Unexpected kernel source commit')
    require(not run(['git', 'status', '--porcelain'], common, True).strip(), 'Kernel source is dirty; start from the pinned source commit')
    makefile = (common / 'Makefile').read_text()
    version = '.'.join(re.search(r'^' + key + r'\s*=\s*(\d+)\s*$', makefile, re.M)[1] for key in ['VERSION', 'PATCHLEVEL', 'SUBLEVEL'])
    require(version == p['kernel_version'], 'Pinned common source version does not match the firmware profile')
    record = kernel.parent / 'build-record'
    record.mkdir(parents=True, exist_ok=True)
    for patch in p['patches']:
        run(['git', 'apply', '--check', public_file(patch)], common)
        run(['git', 'apply', public_file(patch)], common)
    shutil.copyfile(public_file(p['fragment']), common / 'arch/arm64/configs/droidspaces.fragment')
    shutil.copyfile(public_file(p['stock_certificate']), common / 'certs/stock-public.pem')
    # Amend only the aarch64 build target; the first list belongs to that target.
    path = common / 'BUILD.bazel'
    text = path.read_text()
    old = '"module_implicit_outs": get_gki_modules_list("arm64"),'
    require(text.count(old) >= 1, 'Upstream module output declaration changed')
    text = text.replace(old, '"module_implicit_outs": get_gki_modules_list("arm64") + ' + repr(p['modules']) + ',', 1)
    marker = '"android/abi_gki_aarch64_db845c",'
    require(text.count(marker) >= 1, 'Upstream additional KMI list structure changed')
    text = text.replace(marker, marker + '\n        "android/abi_gki_aarch64_droidspaces_cifs",', 1)
    path.write_text(text, encoding='utf-8', newline='\n')
    protected = common / 'android/gki_aarch64_protected_modules'
    protected.write_text('\n'.join(sorted(set(protected.read_text().split()) | set(p['modules']))) + '\n', encoding='utf-8')
    (common / 'android/abi_gki_aarch64_droidspaces_cifs').write_text('[abi_symbol_list]\n' + '\n'.join('  ' + n for n in sorted(p['module_exports'])) + '\n', encoding='utf-8')
    require((common / 'android/abi_gki_protected_exports_aarch64').read_bytes() == public_file(p['protected_exports']).read_bytes(), 'Protected export policy changed upstream; review before building')
    paths = ['include/linux/sched.h', 'arch/arm64/configs/droidspaces.fragment', 'BUILD.bazel',
             'android/abi_gki_aarch64_droidspaces_cifs', 'android/gki_aarch64_protected_modules', 'certs/stock-public.pem']
    run(['git', 'add', *paths], common)
    (record / 'source-changes.patch').write_text(run(['git', 'diff', '--cached'], common, True), encoding='utf-8')
    epoch = run(['git', 'show', '-s', '--format=%ct', 'HEAD'], common, True).strip()
    env = dict(os.environ, GIT_AUTHOR_DATE='@' + epoch + ' +0000', GIT_COMMITTER_DATE='@' + epoch + ' +0000')
    subprocess.run(['git', '-c', 'user.name=Kernel Builder', '-c', 'user.email=kernel-builder@users.noreply.github.com',
                    'commit', '-m', 'Apply versioned Droidspaces adaptation ' + profile_digest(p)], cwd=common, env=env, check=True)
    shutil.copyfile(public_file(p['fragment']), record / 'droidspaces.fragment')
    shutil.copyfile(public_file(p['stock_certificate']), record / 'stock-public.pem')
    write_json(record / 'provenance.json', {'profile': p['id'], 'profile_digest': profile_digest(p),
        'common_commit': p['common_commit'], 'manifest_commit': p['manifest_commit'],
        'prepared_commit': run(['git', 'rev-parse', 'HEAD'], common, True).strip(),
        'project_commit': os.environ.get('GITHUB_SHA', ''), 'run_id': os.environ.get('GITHUB_RUN_ID', ''), 'device_tested': False})
    write_json(record / 'profile.json', p)
    print('Source preparation complete; protected KMI checks remain enabled.')


def finish_build(p, directory):
    dist = artifact_dist(directory)
    record = dist.parent / 'build-record'
    # Configuration is extracted by the pinned kernel's extract-ikconfig in build.sh.
    names = ['Image', '.config', 'System.map', 'vmlinux.symvers', 'kernel_aarch64_Module.symvers'] + [Path(n).name for n in p['modules']]
    write_json(record / 'artifact-hashes.json', {n: sha((dist / n).read_bytes()) for n in names})
    result = verify_build(p, dist)
    write_json(record / 'build-verification.json', {'profile_digest': profile_digest(p), 'device_tested': False,
        'replacement_modules': result['modules'], 'kernel_sha256': result['kernel_sha256'],
        'note': 'Kernel and replacement modules checked. Original vendor modules must also be checked locally before image packaging.'})
    print('Build verification passed, including DNS protection policy and module signatures.')


def add_footer(original, image, part):
    meta = read_avb(original, part)
    args = [sys.executable, ROOT / 'third_party/avbtool.py', 'add_hash_footer', '--image', image,
            '--partition_name', part, '--partition_size', meta['partition_size'], '--algorithm', 'NONE',
            '--hash_algorithm', meta['hash_algorithm'], '--salt', meta['salt'],
            '--rollback_index', meta['rollback_index'], '--rollback_index_location', meta['rollback_index_location'], '--flags', meta['flags']]
    if meta['hash_flags']:
        args.append('--do_not_use_ab')
    for key, value in meta['properties'].items():
        args += ['--prop', key + ':' + value]
    run(args)
    run([sys.executable, ROOT / 'third_party/avbtool.py', 'verify_image', '--image', image])
    new_meta = read_avb(image.read_bytes(), part)
    require(meta == new_meta, 'Repacked AVB metadata changed beyond digest/signing algorithm')


def verify_vendor_contents(original, new, replacements):
    op, ot, oe, of, od, ob = ramdisk.parts(original)
    np, nt, ne, nf, nd, nb = ramdisk.parts(new)
    require(op == np and oe == ne and od == nd and ob == nb and len(of) == len(nf), 'Vendor DTB, bootconfig or fragment structure changed')
    require(original[:24] == new[:24] and original[28:op] == new[28:np], 'Unexpected vendor boot header change')
    changed, processed = [], set()
    for i, (a, b) in enumerate(zip(of, nf)):
        require(ot[i * oe + 8:(i + 1) * oe] == nt[i * ne + 8:(i + 1) * ne], 'Vendor ramdisk table metadata changed')
        old_entries = list(ramdisk.entries(ramdisk.decompress(a))) if a else []
        new_entries = list(ramdisk.entries(ramdisk.decompress(b))) if b else []
        require(len(old_entries) == len(new_entries), 'Vendor archive entry count changed')
        for old, current in zip(old_entries, new_entries):
            name = old['name']
            require(name == current['name'] and old['prefix'] == current['prefix'], 'Vendor archive order/path changed')
            require(all(old['fields'][j] == current['fields'][j] for j in range(13) if j not in (6, 12)), 'Vendor archive file attributes changed')
            require(current['content'] == replacements.get(name, old['content']), 'Unexpected vendor content change: ' + name)
            if name in replacements:
                processed.add(name)
            if old['content'] != current['content']:
                changed.append(name)
    require(processed == set(replacements), 'Not all intended vendor modules were found')
    return changed


def pack(p, directory, output=None, require_provenance=True):
    verified, baseline, report = verify_compatibility(p, directory, require_provenance)
    if output is None:
        output = ROOT / '.local' / 'builds' / p['id'] / (time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    output = Path(output).resolve()
    require(not output.exists(), 'Output directory already exists; refusing to overwrite a prior build')
    output.mkdir(parents=True)
    stage = output / 'images'
    stage.mkdir()
    original_boot = (baseline / 'boot.img').read_bytes()
    kernel = (verified['dist'] / 'Image').read_bytes()
    header = bytearray(original_boot[:4096])
    struct.pack_into('<I', header, 8, len(kernel))
    boot = stage / 'boot.img'
    boot.write_bytes(header + kernel + b'\0' * ((-len(kernel)) % 4096))
    add_footer(original_boot, boot, 'boot')
    new_boot = boot.read_bytes()
    require(new_boot[:8] == original_boot[:8] and new_boot[12:4096] == original_boot[12:4096], 'Unexpected boot header change')
    require(kernel_from_boot(new_boot) == kernel, 'Repacked kernel mismatch')
    original_vendor = (baseline / 'vendor_boot.img').read_bytes()
    replacements = {'lib/modules/' + Path(n).name: (verified['dist'] / Path(n).name).read_bytes() for n in p['modules']}
    vendor_data, fragments = ramdisk.repack(original_vendor, replacements)
    vendor = stage / 'vendor_boot.img'
    vendor.write_bytes(vendor_data)
    add_footer(original_vendor, vendor, 'vendor_boot')
    changed = verify_vendor_contents(original_vendor, vendor.read_bytes(), replacements)
    report.update({'changed_vendor_files': changed, 'avb_hash_verified': True,
                   'image_hashes': {n.name: sha(n.read_bytes()) for n in [boot, vendor]},
                   'baseline_images': p['baseline_images'], 'init_boot_changed': False})
    write_json(output / 'verification.json', report)
    write_json(output / 'profile.json', p)
    (output / 'kernel.config').write_bytes((verified['dist'] / '.config').read_bytes())
    (output / 'README.txt').write_text(
        'Droidspaces kernel candidate - NOT DEVICE TESTED\n'
        f'Device: {p["device"]}; firmware: {p["firmware"]}\n'
        'boot.img and vendor_boot.img are a matched pair. Keep init_boot unchanged.\n'
        'Original images remain in the private local baseline.\n'
        'Verify current firmware, active slot and bootloader unlock status on the actual device before use.\n'
        'CRC and image checks do not prove successful boot, hardware, KernelSU or Droidspaces operation.\n'
        + '\n'.join(report['warnings']) + '\n', encoding='utf-8')
    public_outputs = [boot, vendor, output / 'verification.json', output / 'profile.json', output / 'kernel.config', output / 'README.txt']
    (output / 'SHA256SUMS.txt').write_text('\n'.join(sha(n.read_bytes()) + '  ' + n.name for n in public_outputs) + '\n', encoding='utf-8')
    archive = output / ('Droidspaces-' + p['id'] + '-UNTESTED.zip')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in [*public_outputs, output / 'SHA256SUMS.txt']:
            z.write(path, path.name)
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None, 'Packaged ZIP integrity check failed')
    (output / 'package.sha256').write_text(sha(archive.read_bytes()) + '  ' + archive.name + '\n', encoding='utf-8')
    print('Local compatibility and image packaging completed:', archive)
    print('No partitions were flashed. Device testing is still required.')
    return archive


def rebuild(p, repository):
    validate_baseline(p)
    require(shutil.which('gh'), 'Install GitHub CLI from https://cli.github.com/ and run gh auth login once; then retry')
    run(['gh', 'auth', 'status'])
    request = uuid.uuid4().hex
    run(['gh', 'workflow', 'run', 'build.yaml', '--repo', repository, '--ref', 'main', '-f', 'profile=' + p['id'], '-f', 'request_id=' + request])
    run_id = None
    for _ in range(30):
        runs = json.loads(run(['gh', 'run', 'list', '--repo', repository, '--workflow', 'build.yaml', '--event', 'workflow_dispatch', '--limit', '30', '--json', 'databaseId,displayTitle'], capture=True))
        match = [r for r in runs if request in r['displayTitle']]
        if match:
            run_id = match[0]['databaseId']
            break
        time.sleep(5)
    require(run_id is not None, 'Could not locate dispatched run; inspect GitHub Actions before retrying')
    write_json(ROOT / '.local/last-run.json', {'repository': repository, 'run_id': run_id, 'request_id': request, 'profile': p['id']})
    run(['gh', 'run', 'watch', str(run_id), '--repo', repository, '--exit-status'])
    download = ROOT / '.local/artifacts' / str(run_id)
    run(['gh', 'run', 'download', str(run_id), '--repo', repository, '--name', 'kernel-' + p['id'], '--dir', download])
    return pack(p, download)
