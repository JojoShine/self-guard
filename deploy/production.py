#!/usr/bin/env python3
"""Deployment-only operations. Never source/eval environment files."""
import os, pathlib, stat, subprocess, sys

def read_environment(path):
    file=pathlib.Path(path)
    if stat.S_IMODE(file.stat().st_mode)&0o077:
        raise RuntimeError(str(file)+' must have permissions 0600')
    values={}
    for line in file.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'): continue
        key,separator,value=line.partition('=')
        if not separator or not key.replace('_','').isalnum(): raise RuntimeError('Invalid environment data')
        if key in values: raise RuntimeError('Duplicate environment key')
        values[key]=value
    return values

if __name__=='__main__':
    if sys.argv[1:]!=['bootstrap']: raise SystemExit('Usage: python3 deploy/production.py bootstrap')
    values=read_environment('.env.bootstrap')
    if set(values)!={'ADMIN_EMAIL','ADMIN_PASSWORD'} or len(values['ADMIN_PASSWORD'])<16: raise SystemExit('Invalid bootstrap fields')
    subprocess.run(['docker','compose','--env-file','.env.prod','-f','compose.prod.yaml','run','--rm','--no-deps','-e','ADMIN_EMAIL','-e','ADMIN_PASSWORD','app','/app/bin/bootstrap'],env={**os.environ,**values},check=True)
