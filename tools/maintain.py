#!/usr/bin/env python3
"""Single entry point; never flashes or uploads original device backups."""
from pathlib import Path
import argparse
import json
import sys

if sys.flags.optimize:
    raise SystemExit('Python optimization disables parser checks; run without -O/PYTHONOPTIMIZE')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kernelkit import project as kit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='muyu-os4.0.3.0')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor')
    imp = sub.add_parser('import-baseline')
    for name in ['boot', 'vendor-boot', 'init-boot', 'modules-tar']:
        imp.add_argument('--' + name, required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--kernel', required=True)
    finish = sub.add_parser('verify-build')
    finish.add_argument('--artifact', required=True)
    package = sub.add_parser('pack')
    package.add_argument('--artifact', required=True)
    package.add_argument('--output')
    rebuild = sub.add_parser('rebuild')
    rebuild.add_argument('--repository', default='HenryZhuu/pad7pro-droidspaces-kernel')
    capture = sub.add_parser('capture')
    capture.add_argument('--adb', default='adb')
    new = sub.add_parser('new-profile')
    new.add_argument('--capture', required=True)
    new.add_argument('--id', required=True)
    new.add_argument('--common-commit', required=True)
    new.add_argument('--manifest-commit')
    args = parser.parse_args()
    p = kit.profile(args.profile)
    if args.command == 'doctor':
        print(json.dumps({'profile': p['id'], 'firmware': p['firmware'], 'profile_digest': kit.profile_digest(p), 'device_tested': False}, indent=2))
        if kit.baseline_dir(p).exists():
            kit.validate_baseline(p)
            print('Local original baseline: verified')
        else:
            print('Local original baseline: not imported yet; cloud compilation is available, local packaging requires it')
    elif args.command == 'import-baseline':
        kit.import_baseline(p, args.boot, args.vendor_boot, args.init_boot, args.modules_tar)
    elif args.command == 'prepare':
        kit.prepare_sources(p, args.kernel)
    elif args.command == 'verify-build':
        kit.finish_build(p, args.artifact)
    elif args.command == 'pack':
        kit.pack(p, args.artifact, args.output)
    elif args.command == 'rebuild':
        kit.rebuild(p, args.repository)
    elif args.command == 'capture':
        from kernelkit.capture import capture_device
        capture_device(args.adb)
    elif args.command == 'new-profile':
        from kernelkit.capture import new_profile
        new_profile(p, args.capture, args.id, args.common_commit, args.manifest_commit)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, FileNotFoundError) as exc:
        raise SystemExit(str(exc)) from exc
