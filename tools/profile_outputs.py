from pathlib import Path
import os,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from kernelkit import project as kit
p=kit.profile(sys.argv[1])
values={'id':p['id'],'repo_commit':p['repo_commit'],'common_commit':p['common_commit'],
        'manifest_commit':p['manifest_commit'],'profile_digest':kit.profile_digest(p),
        'source_cache_key':p['manifest_commit']+'-'+p['common_commit']+'-'+p['repo_commit']}
with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f:
    for k,v in values.items():f.write(k+'='+v+'\n')
