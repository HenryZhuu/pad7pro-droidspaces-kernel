"""Explicit read-only device capture, followed by versioned profile creation."""
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from . import project as kit


def capture_device(adb):
    # su is needed to read original partitions; there are no partition write commands.
    adb = str(Path(adb).resolve()) if Path(adb).is_file() else adb
    def shell(command, root=False):
        args = [adb, 'shell', 'su', '-c', command] if root else [adb, 'shell', command]
        return kit.run(args, capture=True).strip()
    kit.run([adb, 'get-state'])
    device = shell('getprop ro.product.device')
    kit.require(device == 'muyu', 'Connected device is not muyu; capture stopped')
    kit.require(shell('id -u', True) == '0', 'Root access is needed for capture; alternatively supply extracted official firmware images and modules')
    firmware = shell('getprop ro.build.version.incremental')
    slot = shell('getprop ro.boot.slot_suffix')
    kit.require(slot in ('_a', '_b'), 'Unexpected active slot')
    kit.require(re.fullmatch('[A-Za-z0-9._-]+', firmware), 'Unexpected firmware identifier')
    destination = kit.ROOT / '.local/captures' / (firmware + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(parents=True)
    remote = '/data/local/tmp/droidspaces-capture-' + uuid.uuid4().hex
    shell('mkdir -m 700 ' + remote + ' && chown 2000:2000 ' + remote, True)
    for part in ['boot', 'vendor_boot', 'init_boot']:
        partition = part + slot
        command = (
            'src=/dev/block/by-name/' + partition + '; '
            '[ -r "$src" ] || src=/dev/block/bootdevice/by-name/' + partition + '; '
            '[ -r "$src" ] && dd if="$src" of=' + remote + '/' + part + '.img bs=1048576 && chmod 644 ' + remote + '/' + part + '.img')
        shell(command, True)
        kit.run([adb, 'pull', remote + '/' + part + '.img', destination / (part + '.img')])
    shell('tar -cf ' + remote + '/stock-modules.tar -C / vendor_dlkm/lib/modules system_dlkm/lib/modules && chmod 644 ' + remote + '/stock-modules.tar', True)
    kit.run([adb, 'pull', remote + '/stock-modules.tar', destination / 'stock-modules.tar'])
    snapshot = {'device': device, 'model': shell('getprop ro.product.model'), 'firmware': firmware,
                'kernel_release': shell('uname -r'), 'slot': slot, 'flash_locked': shell('getprop ro.boot.flash.locked'),
                'images': {n: kit.sha((destination / (n + '.img')).read_bytes()) for n in ['boot', 'vendor_boot', 'init_boot']}}
    kit.write_json(destination / 'device.json', snapshot)
    # Remove only the exact temporary files this capture created, then its empty directory.
    for name in ['boot.img', 'vendor_boot.img', 'init_boot.img', 'stock-modules.tar']:
        shell('rm -f ' + remote + '/' + name, True)
    shell('rmdir ' + remote, True)
    print('Capture saved locally; no device partitions changed:', destination)
    return destination


def new_profile(previous, capture, profile_id, common_commit, manifest_commit=None):
    capture = Path(capture).resolve()
    snapshot = kit.read_json(capture / 'device.json')
    kit.require(snapshot['device'] == 'muyu', 'Unsupported device capture')
    kit.require(re.fullmatch('[a-z0-9][a-z0-9.-]{0,79}', profile_id), 'Invalid profile ID')
    kit.require(re.fullmatch('[0-9a-f]{40}', common_commit), 'Choose and pin a matching upstream common commit')
    profile_path = kit.ROOT / 'profiles' / (profile_id + '.json')
    kit.require(not profile_path.exists(), 'Profile already exists; previous firmware profiles are immutable')
    data = {n: (capture / (n + '.img')).read_bytes() for n in ['boot', 'vendor_boot', 'init_boot']}
    for name, content in data.items():
        kit.require(kit.sha(content) == snapshot['images'][name], 'Capture changed: ' + name)
    certs = kit.scan_boot_certificates(data['boot'])
    modules = list(kit.module_archives([capture / 'stock-modules.tar']))
    certs_with_modules = []
    for cert in certs:
        fp = cert.fingerprint(hashes.SHA256()).hex()
        if any(kit.elf.verify_signature(content, [cert]) == fp for name, content in modules):
            certs_with_modules.append(cert)
    kit.require(len(certs_with_modules) == 1, 'Cannot automatically identify a unique original module trust certificate; review required')
    release = snapshot['kernel_release']
    match = re.match(r'(6\.1\.\d+)-android14-', release)
    kit.require(match, 'Kernel family changed; this adaptation must be reviewed before reuse')
    p = dict(previous, id=profile_id, firmware=snapshot['firmware'], stock_kernel_release=release,
             kernel_version=match[1], common_commit=common_commit, baseline_images=snapshot['images'], device_tested=False)
    if manifest_commit:
        kit.require(re.fullmatch('[0-9a-f]{40}', manifest_commit), 'Invalid manifest commit')
        p['manifest_commit'] = manifest_commit
    p['stock_certificate'] = 'profiles/certs/' + profile_id + '.pem'
    p['stock_certificate_der_sha256'] = certs_with_modules[0].fingerprint(hashes.SHA256()).hex()
    (kit.ROOT / p['stock_certificate']).write_bytes(certs_with_modules[0].public_bytes(serialization.Encoding.PEM))
    kit.write_json(profile_path, p)
    kit.profile(profile_id)
    kit.import_baseline(p, capture / 'boot.img', capture / 'vendor_boot.img', capture / 'init_boot.img', capture / 'stock-modules.tar')
    print('New profile created. Review the common/manifest pins and SYSVIPC patch before committing public profile files.')
