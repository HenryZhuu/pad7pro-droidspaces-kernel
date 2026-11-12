"""Export only reviewed public project paths; never include .local or .venv."""
from pathlib import Path
import argparse,json,re,zipfile
ROOT=Path(__file__).resolve().parents[1]
TOP={'kernelkit','tools','profiles','configs','patches','third_party','.github','tests','docs'}
FILES={'.gitignore','.gitattributes','README.md','maintain.ps1','requirements.txt','requirements-dev.txt'}

def public_files():
    paths=[ROOT/n for n in FILES if (ROOT/n).is_file()]
    for name in TOP:
        if (ROOT/name).is_dir():paths.extend((ROOT/name).rglob('*'))
    for p in sorted(paths):
        relative=p.relative_to(ROOT)
        if not p.is_file() or '__pycache__' in relative.parts or p.suffix=='.pyc':continue
        resolved=p.resolve()
        if not resolved.is_relative_to(ROOT.resolve()) or '.local' in resolved.relative_to(ROOT.resolve()).parts:
            raise ValueError('Refusing a link outside public source paths: '+str(relative))
        if relative.parts[0] in TOP or len(relative.parts)==1:
            content=p.read_text(encoding='utf-8')
            if re.search(r'^-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----$',content,re.M):
                raise ValueError('Refusing to publish a private key: '+str(relative))
            yield relative.as_posix(),content

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--json');parser.add_argument('--zip');args=parser.parse_args()
    files=list(public_files())
    if args.json:
        Path(args.json).write_text(json.dumps([{'path':n,'mode':'100644','type':'blob','content':c} for n,c in files],ensure_ascii=True),encoding='utf-8')
    if args.zip:
        with zipfile.ZipFile(args.zip,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for n,c in files:z.writestr(n,c.encode('utf-8'))
    print('Exported',len(files),'public source files. Private baseline, environment and images excluded.')
