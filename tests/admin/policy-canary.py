#!/usr/bin/env python3
"""Phase-4 real policy probes; owns every container, file and network it mutates."""
from pathlib import Path
import json, os, secrets, shutil, subprocess, sys, tempfile, time
ROOT=Path(__file__).resolve().parents[2]
CASE=sys.argv[1]
assert CASE in ('rate-policy','challenge-secret')
RUN=f'pingap-policy-{os.getpid()}-{time.time_ns()}'
OUT=Path(tempfile.mkdtemp(prefix='policy.',dir=ROOT/'.cross-review/implementation'))
for name in ['conf','data','keys','browser-results']:(OUT/name).mkdir()
IMAGE=os.environ.get('PINGAP_CANARY_IMAGE','pingap-native-canary:phase4-checkpoint')
def docker(*args,check=True):return subprocess.run(['docker',*args],capture_output=True,text=True,check=check).stdout.strip()
def services():return sorted(docker('ps','--format','{{.ID}} {{.Names}} {{.Image}}').splitlines())
before=services();(OUT/'services-before.json').write_text(json.dumps(before))
password=secrets.token_hex(24)
(OUT/'candidate.env').write_text(f'PINGAP_ADMIN_ADDR=0.0.0.0:3018?store=/var/lib/pingap/canary.db\nPINGAP_ADMIN_USER=canary-admin\nPINGAP_ADMIN_PASSWORD={password}\nPINGAP_CONF=/opt/pingap/conf\nPINGAP_AUTORELOAD=true\nPINGAP_DISABLE_ACME=1\nRUST_LOG=error,main::auto_restart=debug\n')
(OUT/'tester.env').write_text(f'PASSWORD={password}\nPINGAP_E2E_PASSWORD={password}\nPINGAP_E2E_URL=http://candidate:3018\n')
for name in ['candidate.env','tester.env']:os.chmod(OUT/name,0o600)
del password
keys=[]
for name in ['challenge-v1','challenge-v2']:
    key=secrets.token_hex(32).encode();keys.append(key)
    fd=os.open(OUT/'keys'/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
    with os.fdopen(fd,'wb') as stream:stream.write(key)
# Listeners are process-start services; this scenario exercises policy hot reload
# on a provisioned listener, not adding a listening socket at runtime.
# Legacy-source rotation is checked at DEBUG logging, too. These test-only
# literals are never retained in evidence or shared with the operator's services.
for name in ['LEGACY_KEY_ONE','LEGACY_KEY_TWO']:
    value=secrets.token_hex(32);keys.append(value.encode())
    with (OUT/'tester.env').open('a') as stream:stream.write(f'{name}={value}\n')
(OUT/'conf/basic.toml').write_text('[basic]\nthreads=1\nname="isolated-policy-canary"\nlog_level="ERROR,main::auto_restart=DEBUG"\n[servers.http]\naddr="0.0.0.0:8080"\nlocations=[]\n')
(OUT/'fixture.js').write_text("require('http').createServer((q,s)=>s.end('fixture')).listen(8081,'0.0.0.0')")
owned=[]
try:
    (OUT/'image-id.txt').write_text(docker('image','inspect',IMAGE,'--format','{{.Id}}'))
    docker('network','create','--label',f'pingap.canary={RUN}',RUN)
    fixture=RUN+'-fixture';owned.append(fixture)
    docker('run','-d','--name',fixture,'--network',RUN,'--network-alias','fixture','--label',f'pingap.canary={RUN}','--read-only','--memory','128m','--cpus','1','-v',f'{OUT}/fixture.js:/fixture.js:ro','node:24-alpine','node','/fixture.js')
    candidate=RUN+'-candidate';owned.append(candidate)
    docker('run','-d','--name',candidate,'--network',RUN,'--network-alias','candidate','--label',f'pingap.canary={RUN}','--read-only','--memory','1g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--env-file',str(OUT/'candidate.env'),'-v',f'{OUT}/conf:/opt/pingap/conf','-v',f'{OUT}/data:/var/lib/pingap','-v',f'{OUT}/keys:/run/secrets/pingap/challenge:ro',IMAGE)
    tester=RUN+'-tester';owned.append(tester)
    with (OUT/'client.log').open('w') as log:
        common=['docker','run','--rm','--name',tester,'--network',RUN,'--label',f'pingap.canary={RUN}','--env-file',str(OUT/'tester.env')]
        if CASE=='rate-policy':
            command=common+['-v',f'{ROOT}/web:/source:ro','-v',f'{OUT}/browser-results:/work/test-results','-w','/work','mcr.microsoft.com/playwright:v1.64.1-noble','bash','-c',"set -euo pipefail; tar -C /source --exclude=node_modules --exclude=dist --exclude=test-results --exclude=playwright-report --exclude=.env* --exclude=.npmrc -cf - . | tar -C /work -xf -; npm ci --no-audit --no-fund && npm run test:e2e -- rate-policy.spec.ts"]
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
        else:
            command=common+['-v',f'{ROOT}/tests/admin/challenge-secret-client.js:/client.js:ro','-v',f'{OUT}:/out','node:24-alpine','node','/client.js']
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            for signal,done in [('restart-v1','restarted-v1'),('restart-pending','restarted-pending'),('remove-v1','removed-v1')]:
                deadline=time.monotonic()+180
                while not (OUT/signal).exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.1)
                if not (OUT/signal).exists():raise RuntimeError('missing challenge coordination '+signal)
                if signal=='restart-v1':docker('restart',candidate)
                elif signal=='restart-pending':
                    docker('kill','--signal','KILL',candidate);docker('start',candidate)
                else:(OUT/'keys/challenge-v1').unlink()
                (OUT/done).write_text('ready')
            if process.wait(timeout=180)!=0:raise RuntimeError('challenge client failed; inspect isolated client.log')
    after=sorted(line for line in services() if not any(f' {name} ' in line for name in owned))
    (OUT/'services-after.json').write_text(json.dumps(after));assert before==after,'unrelated service inventory changed'
finally:
    leaked=False
    for name in reversed(owned):
        if docker('inspect',name,'--format','{{index .Config.Labels "pingap.canary"}}',check=False)==RUN:
            logs=subprocess.run(['docker','logs',name],capture_output=True)
            raw=logs.stdout+logs.stderr
            leaked=leaked or any(key in raw for key in keys)
            for key in keys:raw=raw.replace(key,b'[REDACTED_TEST_KEY]')
            (OUT/(name+'.log')).write_bytes(raw)
            docker('rm','-f',name,check=False)
    if docker('network','inspect',RUN,'--format','{{index .Labels "pingap.canary"}}',check=False)==RUN:docker('network','rm',RUN,check=False)
    for name in ['candidate.env','tester.env']:(OUT/name).unlink(missing_ok=True)
    for path in (OUT/'keys').iterdir():path.unlink()
    # Candidate config/store versions intentionally contained ephemeral legacy
    # fixtures. Retain proof JSON/logs, not confidential test snapshots.
    docker('run','--rm','--network','none','-v',f'{OUT}/conf:/owned/conf','-v',f'{OUT}/data:/owned/data','node:24-alpine','chown','-R',f'{os.getuid()}:{os.getgid()}','/owned/conf','/owned/data')
    shutil.rmtree(OUT/'conf');shutil.rmtree(OUT/'data')
    if CASE=='rate-policy':docker('run','--rm','--network','none','-v',f'{OUT}/browser-results:/artifacts','node:24-alpine','chown','-R',f'{os.getuid()}:{os.getgid()}','/artifacts')
    subprocess.run(['python3',str(ROOT/'tests/admin/sanitize-artifacts.py'),str(OUT),str(OUT/'browser-results')],check=True)
    if leaked:raise RuntimeError('key material leaked in candidate logs (evidence redacted)')

print('RATE_POLICY_PASS' if CASE=='rate-policy' else 'CHALLENGE_SECRET_PASS')
