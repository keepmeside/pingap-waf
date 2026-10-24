#!/usr/bin/env python3
"""Real candidate API/history checks, using exclusively run-owned resources."""
from pathlib import Path
import json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
ROOT=Path(__file__).resolve().parents[2]
CASE=sys.argv[1]
assert CASE in ('native-ban-api','native-history-storage')
RUN=f'pingap-native-api-{os.getpid()}-{time.time_ns()}'
OUT=Path(tempfile.mkdtemp(prefix='native-api.',dir=ROOT/'.cross-review/implementation'))
CONF=OUT/'conf';CONF.mkdir();(OUT/'data').mkdir()
IMAGE=os.environ.get('PINGAP_CANARY_IMAGE','pingap-native-canary:phase3')
def docker(*args,check=True):
    p=subprocess.run(['docker',*args],capture_output=True,text=True,check=check)
    return p.stdout.strip()
def services():return sorted(docker('ps','--format','{{.ID}} {{.Names}} {{.Image}}').splitlines())
before=services();(OUT/'services-before.json').write_text(json.dumps(before))
password=secrets.token_hex(24);key=urllib.parse.quote(__import__('base64').b64encode(secrets.token_bytes(32)).decode(),safe='')
(OUT/'candidate.env').write_text(f'PINGAP_ADMIN_ADDR=0.0.0.0:3018?store=/var/lib/pingap/canary.db&totp_key={key}\nPINGAP_ADMIN_USER=canary-admin\nPINGAP_ADMIN_PASSWORD={password}\nPINGAP_CONF=/opt/pingap/conf\nPINGAP_AUTORELOAD=true\nPINGAP_DISABLE_ACME=1\n')
(OUT/'tester.env').write_text(f'CASE={CASE}\nPASSWORD={password}\n')
for name in ['candidate.env','tester.env']:os.chmod(OUT/name,0o600)
del password,key
config='[basic]\nthreads=1\n[servers.test]\naddr="0.0.0.0:8080"\nlocations=["scan","guard","detect","control"]\n[upstreams.fixture]\naddrs=["fixture:8081"]\n'
for name in ['scan','guard','detect','control']:
    config+=f'[locations.{name}]\nhost="{name}.test"\nupstream="fixture"\n'
    if name!='control':config+=f'plugins=["behaviour:{name}"]\n'
for name in ['scan','guard','detect']:
    mode='detect' if name=='detect' else 'block'
    ttl='20ms' if CASE=='native-history-storage' and name=='scan' else '10m'
    config+=f'[plugins."behaviour:{name}"]\ncategory="behaviour"\nenabled=true\nclient_ip_from_peer=true\nabuse_namespace="behaviour:{name}"\n[plugins."behaviour:{name}".abuse]\nenabled=true\n[plugins."behaviour:{name}".abuse.scan]\nmode="{mode}"\nwindow="10s"\nthreshold=2\nban_ttl="{ttl}"\n'
(CONF/'pingap.toml').write_text(config)
(OUT/'fixture.js').write_text("require('http').createServer((q,s)=>{s.statusCode=q.url.startsWith('/missing')?404:200;s.end('fixture')}).listen(8081,'0.0.0.0');")
CLIENT=r'''
const fs=require('fs'),http=require('http'),crypto=require('crypto');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
function check(condition,label){if(!condition)throw Error(label)}
async function call(port,path,method='GET',body=null,token=null,host=null){
 const data=body===null?null:JSON.stringify(body);
 return new Promise((resolve,reject)=>{
  const headers={};if(data){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(data)}
  if(token)headers.Authorization='Bearer '+token;if(host)headers.Host=host;
  const q=http.request({hostname:'candidate',port,path,method,headers},r=>{let text='';r.on('data',c=>text+=c);r.on('end',()=>{let json=null;try{json=JSON.parse(text)}catch{}resolve({status:r.statusCode,json})})});q.on('error',reject);q.setTimeout(15000,()=>q.destroy(Error('request timeout')));q.end(data);
 });
}
let token;
const api=(path,method='GET',body=null,t=token)=>call(3018,'/api'+path,method,body,t);
const traffic=(host,path='/')=>call(8080,path,'GET',null,null,host+'.test');
async function eventually(fn,label){for(let i=0;i<100;i++){if(await fn())return;await pause(200)}throw Error(label)}
async function login(username='canary-admin'){const r=await api('/auth/login','POST',{username,password:process.env.PASSWORD},null);check(r.status===200,'login');return r.json}
async function createBan(host='scan'){check((await traffic(host,'/missing/one')).status===404,'first upstream404');check((await traffic(host,'/missing/two')).status===404,'second upstream404')}
const nativeRows=async()=>{const r=await api('/activity?limit=1000');check(r.status===200,'history readable');return r.json.filter(e=>e.action.startsWith('native.'))};
function code(secret){const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const ch of secret.toUpperCase().replace(/=+$/,''))bits+=alphabet.indexOf(ch).toString(2).padStart(5,'0');let bytes=[];for(let i=0;i+8<=bits.length;i+=8)bytes.push(parseInt(bits.slice(i,i+8),2));const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const hash=crypto.createHmac('sha1',Buffer.from(bytes)).update(counter).digest();const offset=hash[19]&15;return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0')}
(async()=>{
 await eventually(async()=>{try{return (await call(3018,'/api/health')).status===200}catch{return false}},'candidate readiness');
 token=(await login()).token;
 check((await api('/abuse/bans','GET',null,null)).status===401,'unauthenticated401');
 if(process.env.CASE==='native-ban-api'){
  check((await api('/users','POST',{username:'canary-viewer',email:'viewer@example.test',password:process.env.PASSWORD,role:'viewer'})).status===200,'create isolated viewer');
  const viewer=(await login('canary-viewer')).token;
  await createBan('detect');check((await traffic('detect','/benign')).status===200,'detect never blocks');
  await createBan();
  await pause(1500);
  check((await nativeRows()).some(e=>e.action==='native.abuse.detected'),'permanent native detection history');
  const findings=await api('/logs/waf-events');check(findings.status===200,'findings readable');check(!findings.json.some(e=>e.blocked&&e.profile==='behaviour:scan'),'creation is not a block request');
  check((await traffic('scan')).status===403,'actual active403');check((await traffic('control')).status===200,'control200');
  const beforeRestart=await api('/abuse/bans');check(beforeRestart.status===200&&beforeRestart.json.items.length===1,'list actual ban before restart');
  fs.writeFileSync('/out/restart-active','ready');
  await eventually(()=>Promise.resolve(fs.existsSync('/out/restart-complete')),'candidate restart coordination');
  await eventually(async()=>{try{return (await call(3018,'/api/health')).status===200}catch{return false}},'candidate ready after restart');
  token=(await login()).token;
  const afterRestart=await api('/abuse/bans');
  check(afterRestart.status===200&&afterRestart.json.items.length===0,'restart clears active bans');
  check(afterRestart.json.epoch&&afterRestart.json.epoch!==beforeRestart.json.epoch,'restart advances native epoch');
  check((await traffic('scan')).status===200,'post-restart request allowed');
  await createBan();
  const page=await api('/abuse/bans');check(page.status===200&&page.json.items.length===1,'list actual ban');const ban=page.json.items[0];
  const owner={profile:ban.profile,domain:ban.domain,client_ip:ban.client_ip};
  check((await api('/abuse/bans','GET',null,viewer)).status===200,'viewer read');
  check((await api('/abuse/bans/'+ban.id,'DELETE',owner,viewer)).status===403,'viewer release403');
  const setup=await api('/account/2fa/setup','POST',{});check(setup.status===200,'totp setup');
  const secret=new URL(setup.json.otpauth_uri).searchParams.get('secret');
  check((await api('/account/2fa/enable','POST',{code:code(secret)})).status===204,'totp enable');
  token=(await login()).token;
  check((await api('/abuse/bans/'+ban.id,'DELETE',owner)).status===403,'pending second factor403');
  await pause(31000);
  check((await api('/auth/totp','POST',{code:code(secret)})).status===204,'complete second factor');
  const released=await api('/abuse/bans/'+ban.id,'DELETE',owner);
  check(released.status===200&&released.json.outcome==='released'&&released.json.audit==='queued','release queued');
  const absent=await api('/abuse/bans/'+ban.id,'DELETE',owner);check(absent.status===200&&absent.json.outcome==='already_absent','retry already absent');
  check((await traffic('scan','/benign')).status===200,'release restores200');
  await eventually(async()=>{const rows=await nativeRows();return rows.filter(e=>e.action==='native.ban.released'&&e.target===ban.id&&e.actor_username==='canary-admin').length===1},'release permanent actor');
  fs.writeFileSync('/out/result.json',JSON.stringify({case:process.env.CASE,detect_history:true,epoch:page.json.epoch,restart_epoch_before:beforeRestart.json.epoch,restart_epoch_after:afterRestart.json.epoch,restart_reset:true,post_restart_allowed:true,release:released.json,rbac:true,totp:true,metric_integrity:true}));
 }else{
  const sizes=()=>{const entries=fs.readdirSync('/db').filter(n=>n.startsWith('canary.db'));return Object.fromEntries(entries.map(n=>[n,fs.statSync('/db/'+n).size]))};
  const before=sizes(),start=Date.now();
  await createBan('detect');check((await traffic('detect','/benign')).status===200,'storage detect never blocks');
  await createBan('guard');
  const sampleBan=(await api('/abuse/bans?profile=behaviour%3Aguard')).json.items[0];
  const sampleRelease=await api('/abuse/bans/'+sampleBan.id,'DELETE',{profile:sampleBan.profile,domain:sampleBan.domain,client_ip:sampleBan.client_ip});
  check(sampleRelease.status===200&&sampleRelease.json.outcome==='released','representative operator release');
  for(let i=0;i<80;i++){await createBan();await pause(25)}
  await traffic('scan','/benign');
  await eventually(async()=> (await nativeRows()).length>=163,'history growth flush');
  const rows=await nativeRows(),grown=sizes();const elapsed=(Date.now()-start)/1000;
  const fd=fs.openSync('/db/.native-test-pressure','wx');const chunk=Buffer.alloc(65536);let pressure=0;
  try{for(;;){const n=fs.writeSync(fd,chunk);if(n===0)break;pressure+=n}}catch(e){check(e.code==='ENOSPC','finite test disk pressure')}finally{fs.closeSync(fd)}
  await createBan('guard');check((await traffic('guard')).status===403,'disk-full runtime403');
  const pendingGuard=(await api('/abuse/bans?profile=behaviour%3Aguard')).json.items[0];
  await eventually(async()=>{const m=await api('/metrics/detection');return m.status===200&&m.json.native_event_delivery.lifecycle_write_failures>0},'explicit writer failure');
  const readable=await nativeRows();check(rows.every(row=>readable.some(r=>r.id===row.id)),'committed rows survive disk full');
  const failure=await api('/users','POST',{username:'full-disk-user',email:'full@example.test',password:process.env.PASSWORD,role:'viewer'});check(failure.status>=500,'admin write error on full disk');
  const degraded=(await api('/metrics/detection')).json.native_event_delivery;
  fs.unlinkSync('/db/.native-test-pressure');
  await eventually(async()=> (await nativeRows()).some(e=>e.action==='native.ban.created'&&e.target===pendingGuard.id),'writer resumes after capacity restored');
  check((await traffic('guard')).status===403,'protection survives storage recovery');
  const after=await nativeRows();check(rows.every(row=>after.some(r=>r.id===row.id)),'no history purged');
  const delta=Object.values(grown).reduce((a,b)=>a+b,0)-Object.values(before).reduce((a,b)=>a+b,0);
  const bytesPerRow=delta/rows.length;
  fs.writeFileSync('/out/result.json',JSON.stringify({case:process.env.CASE,lifecycle_types:[...new Set(rows.map(r=>r.action))],configured_metadata:{profile:sampleBan.profile,domain:sampleBan.domain,client_ip:sampleBan.client_ip,actor_username:'canary-admin'},rows:rows.length,seconds:elapsed,rows_per_second:rows.length/elapsed,files_before:before,files_after:grown,incremental_bytes_per_row:bytesPerRow,measurement_kind:'database_plus_uncheckpointed_wal',projection_at_one_transition_per_second:{day:bytesPerRow*86400,days30:bytesPerRow*86400*30,days365:bytesPerRow*86400*365},pressure_bytes:pressure,admin_write_status:failure.status,delivery:degraded,recovery:true,retained_previous_rows:true}));
 }
 console.log('NATIVE_API_CLIENT_PASS');
})().catch(e=>{console.error(e.message);process.exitCode=1});
'''
(OUT/'client.js').write_text(CLIENT)
owned=[];volume=None
try:
    (OUT/'image-id.txt').write_text(docker('image','inspect',IMAGE,'--format','{{.Id}}'))
    docker('network','create','--label',f'pingap.canary={RUN}',RUN)
    if CASE=='native-history-storage':
        volume=RUN+'-store';docker('volume','create','--label',f'pingap.canary={RUN}','--driver','local','--opt','type=tmpfs','--opt','device=tmpfs','--opt','o=size=16m',volume)
    data=volume or str(OUT/'data')
    fixture=RUN+'-fixture';owned.append(fixture)
    docker('run','-d','--name',fixture,'--network',RUN,'--network-alias','fixture','--label',f'pingap.canary={RUN}','--read-only','--memory','128m','--cpus','1','-v',f'{OUT}/fixture.js:/fixture.js:ro','node:24-alpine','node','/fixture.js')
    candidate=RUN+'-candidate';owned.append(candidate)
    docker('run','-d','--name',candidate,'--network',RUN,'--network-alias','candidate','--label',f'pingap.canary={RUN}','--read-only','--memory','1g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--env-file',str(OUT/'candidate.env'),'-v',f'{CONF}:/opt/pingap/conf:ro','-v',f'{data}:/var/lib/pingap',IMAGE)
    tester=RUN+'-tester';owned.append(tester)
    command=['docker','run','--rm','--name',tester,'--network',RUN,'--label',f'pingap.canary={RUN}','--env-file',str(OUT/'tester.env'),'-v',f'{OUT}/client.js:/client.js:ro','-v',f'{OUT}:/out','-v',f'{data}:/db','node:24-alpine','node','/client.js']
    with (OUT/'client.log').open('w') as log:
        if CASE == 'native-ban-api':
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+120
            while not (OUT/'restart-active').exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.1)
            if not (OUT/'restart-active').exists():
                raise RuntimeError('missing active-ban restart coordination')
            docker('restart',candidate)
            (OUT/'restart-complete').write_text('ready')
            if process.wait(timeout=240)!=0:
                raise RuntimeError('native API client failed; inspect isolated client.log')
        else:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=240)
    after=sorted(line for line in services() if not any(f' {name} ' in line for name in owned))
    (OUT/'services-after.json').write_text(json.dumps(after));assert after==before,'unrelated services changed'
    print('NATIVE_BAN_API_PASS' if CASE=='native-ban-api' else 'NATIVE_HISTORY_STORAGE_PASS')
finally:
    for name in reversed(owned):
        if docker('inspect',name,'--format','{{index .Config.Labels "pingap.canary"}}',check=False)==RUN:
            p=subprocess.run(['docker','logs',name],capture_output=True,text=True)
            # Never retain credentials; application logs should not contain any either.
            (OUT/(name+'.log')).write_text(p.stdout+p.stderr)
            docker('rm','-f',name,check=False)
    if docker('network','inspect',RUN,'--format','{{index .Labels "pingap.canary"}}',check=False)==RUN:docker('network','rm',RUN,check=False)
    if volume and docker('volume','inspect',volume,'--format','{{index .Labels "pingap.canary"}}',check=False)==RUN:docker('volume','rm',volume,check=False)
    subprocess.run(['python3',str(ROOT/'tests/admin/sanitize-artifacts.py'),str(OUT),str(OUT)],check=True)
    for name in ['candidate.env','tester.env']:(OUT/name).unlink(missing_ok=True)
