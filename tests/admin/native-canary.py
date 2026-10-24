#!/usr/bin/env python3
"""Real native request/response canary, isolated from all deployed services."""
from pathlib import Path
import json, os, subprocess, sys, tempfile, time
ROOT=Path(__file__).resolve().parents[2]
CASE=sys.argv[1]
if CASE not in ("native-scenario","policy-unavailable-behaviour","policy-unavailable-limit"):
    raise SystemExit("Unsupported native canary")
IMAGE=os.environ.get("PINGAP_CANARY_IMAGE","pingap-native-canary:phase2")
RUN=f"pingap-native-{os.getpid()}-{time.time_ns()}"
OUT=Path(tempfile.mkdtemp(prefix="native.",dir=ROOT/".cross-review/implementation"))
CONF=OUT/"conf";CONF.mkdir()
def docker(*args,check=True):
    return subprocess.run(["docker",*args],capture_output=True,text=True,check=check).stdout.strip()
def services():
    return sorted(docker("ps","--format","{{.ID}} {{.Names}} {{.Image}}").splitlines())
owned=[]
before=services();(OUT/"services-before.json").write_text(json.dumps(before))
def configuration(fail_open=False,edited=False,disabled=False,unrelated=False):
    if CASE=="policy-unavailable-limit":
        text='[basic]\nthreads=1\n'+('on_policy_unavailable="fail_open"\n' if fail_open else '')
        names=['broken','control','advisory','legacy','reload']
        text+='[servers.canary]\naddr="0.0.0.0:8080"\nlocations='+json.dumps(names)+'\n[upstreams.fixture]\naddrs=["fixture:8081"]\n'
        for name in names:
            text+=f'[locations.{name}]\nhost="{name}.test"\nupstream="fixture"\n'
            if name!='control': text+=f'plugins=["limit:{name}"]\n'
        for name in ['broken','advisory','legacy','reload']:
            interval='invalid' if name in ['broken','advisory'] or (name=='reload' and edited) else '10s'
            text+=f'[plugins."limit:{name}"]\ncategory="limit"\ntype="inflight"\ntag="ip"\nmax={0 if name=="legacy" else 100000}\ninterval="{interval}"\n'
            if name in ['broken','reload']:text+='enforcement_required=true\n'
        return text
    basic='[basic]\nname="isolated-native-canary"\nthreads=1\n'
    if fail_open:basic+='on_policy_unavailable="fail_open"\n'
    text=basic+'[servers.canary]\naddr="0.0.0.0:8080"\nlocations=["login","scan","double","detect","control","reload","broken","malformed","advisory","legacy","waf"]\n[upstreams.fixture]\naddrs=["fixture:8081"]\n'
    for name,policies in {"login":["behaviour:login"],"scan":["behaviour:scan"],"double":["behaviour:scan","behaviour:login"],"detect":["behaviour:detect"],"control":[],"reload":["behaviour:reload"],"broken":["behaviour:broken"],"malformed":["behaviour:malformed"],"advisory":["behaviour:advisory"],"legacy":["behaviour:legacy"],"waf":["waf:strict"]}.items():
        text+=f'[locations.{name}]\nhost="{name}.test"\nupstream="fixture"\nplugins={json.dumps(policies)}\n'
    for name,scenario,mode in [("login","failed_login","block"),("scan","scan","block"),("detect","scan","detect"),("reload","scan","block"),("broken","scan","block"),("malformed","scan","detect"),("advisory","scan","detect")]:
        threshold=0 if name in ("broken","malformed") else (10 if name=="reload" and edited else 3)
        if name=="detect" and unrelated:threshold=4
        ttl="60s" if name=="reload" else "3s"
        enabled='false' if disabled and name=="reload" else 'true'
        text+=f'[plugins."behaviour:{name}"]\ncategory="behaviour"\nenabled={enabled}\nclient_ip_from_peer=true\nabuse_namespace="behaviour:{name}"\n[plugins."behaviour:{name}".abuse]\nenabled=true\n[plugins."behaviour:{name}".abuse.{scenario}]\nmode="{mode}"\nwindow="2s"\nthreshold={threshold}\nban_ttl="{ttl}"\n'
        if scenario=="failed_login":text+='path="/login"\nmethod="POST"\nstatuses=[401]\n'
    text+='[plugins."waf:strict"]\ncategory="waf"\nbudget_ms=10000\n[plugins."waf:strict".categories]\nsql_injection="block"\n'
    text+='[plugins."behaviour:legacy"]\ncategory="behaviour"\nenabled=true\nclient_ip_from_peer=true\nbudget_ms=0\n'
    return text
(OUT/"fixture.js").write_text("require('http').createServer((q,s)=>{s.statusCode=q.method==='POST'&&q.url==='/login'?401:q.url.startsWith('/missing')?404:200;s.end('fixture');}).listen(8081,'0.0.0.0');")
# The same tester container supplies the same actual peer address across every call.
CLIENT=r"""
const fs=require('fs');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
let sequence=0;
async function request(host,path='/',method='GET') {
 return await new Promise((resolve,reject)=>{require('http').request({hostname:'candidate',port:8080,path,method,headers:{host:host+'.test','x-forwarded-for':`198.51.100.${++sequence%200}`}},response=>{response.resume();response.on('end',()=>resolve(response.statusCode));}).on('error',reject).end();});
}
async function expect(host,path,method,status) {const actual=await request(host,path,method);if(actual!==status)throw Error(`${host} ${method} ${path}: expected ${status}, got ${actual}`);}
async function ready(){for(let i=0;i<100;i++){try{if(await request('control')===200)return;}catch{}await pause(100);}throw Error('candidate not ready');}
(async()=>{
 await ready();
 if(process.env.CASE.startsWith('policy-unavailable-')) {
  const status=process.env.OPEN==='1'?200:503;
  await expect('broken','/','GET',status);await expect('control','/','GET',200);
  await expect('advisory','/','GET',200);if(process.env.CASE==='policy-unavailable-behaviour')await expect('malformed','/','GET',status);await expect('legacy','/','GET',process.env.CASE==='policy-unavailable-limit'?429:200);
  if(process.env.CASE==='policy-unavailable-limit') {
   await expect('reload','/','GET',200);fs.writeFileSync('/coord/ready-limit','ready');
   for(let i=0;i<500 && !fs.existsSync('/coord/reload-bad');i++)await pause(100);
   await expect('reload','/','GET',status);await expect('control','/','GET',200);
   fs.writeFileSync('/coord/refused-limit','ready');
   for(let i=0;i<500 && !fs.existsSync('/coord/reload-fixed');i++)await pause(100);
   await expect('reload','/','GET',200);await expect('legacy','/','GET',429);
  }
 } else {
  for(let i=0;i<3;i++)await expect('login','/login','POST',401);
  await expect('login','/','GET',403);await expect('control','/','GET',200);
  for(let i=0;i<20;i++)await expect('scan','/missing?s='+i,'GET',404);
  await expect('scan','/missing/2','GET',404);await expect('scan','/missing/3','GET',404);
  await expect('scan','/','GET',403);
  await expect('waf', '/?id=1%27%20OR%20%271%27%3D%271', 'GET', 403);
  for(let i=0;i<5;i++)await expect('detect','/missing/'+i,'GET',404);
  await expect('detect','/','GET',200);
  await pause(3100);await expect('login','/','GET',200);await expect('scan','/','GET',200);
  for(let i=0;i<3;i++)await expect('reload','/missing/'+i,'GET',404);
  await expect('reload','/','GET',403);
  fs.writeFileSync('/coord/ready','ready');
  for(let i=0;i<400 && !fs.existsSync('/coord/unrelated');i++)await pause(100);
  await expect('reload','/','GET',403);fs.writeFileSync('/coord/retained','retained');
  for(let i=0;i<400 && !fs.existsSync('/coord/edited');i++)await pause(100);
  await expect('reload','/','GET',200);fs.writeFileSync('/coord/reset','ready');
  for(let i=0;i<400 && !fs.existsSync('/coord/duplicate');i++)await pause(100);
  await expect('reload','/','GET',503);
 }
 console.log('NATIVE_CLIENT_PASS');
})().catch(e=>{console.error(e.message);process.exit(1);});
"""
(OUT/"client.js").write_text(CLIENT)
try:
    if os.environ.get("PINGAP_CANARY_SKIP_BUILD")!="1":
        with (OUT/"build.log").open('w') as log:subprocess.run(["docker","build","-t",IMAGE,str(ROOT)],stdout=log,stderr=subprocess.STDOUT,check=True)
    (OUT/"image-id.txt").write_text(docker("image","inspect",IMAGE,"--format","{{.Id}}"))
    docker("network","create","--label",f"pingap.canary={RUN}",RUN)
    fixture=RUN+"-fixture";owned.append(fixture)
    docker("run","-d","--name",fixture,"--network",RUN,"--network-alias","fixture","--label",f"pingap.canary={RUN}","--read-only","--cpus","1","--memory","128m","-v",f"{OUT}/fixture.js:/fixture.js:ro","node:24-alpine","node","/fixture.js")
    for open_mode in ([False,True] if CASE.startswith("policy-unavailable-") else [False]):
        for signal in ['ready-limit','reload-bad','refused-limit','reload-fixed']:
            (OUT/signal).unlink(missing_ok=True)
        (CONF/"pingap.toml").write_text(configuration(open_mode))
        candidate=RUN+("-open" if open_mode else "-closed");owned.append(candidate)
        docker("run","-d","--name",candidate,"--network",RUN,"--network-alias","candidate","--label",f"pingap.canary={RUN}","--read-only","--cpus","2","--memory","1g","--tmpfs","/tmp:rw,nosuid,nodev,size=64m","-e","PINGAP_CONF=/opt/pingap/conf","-e","PINGAP_AUTORELOAD=true","-e","PINGAP_DISABLE_ACME=1","-v",f"{CONF}:/opt/pingap/conf:ro",IMAGE)
        tester=RUN+"-tester";owned.append(tester)
        cmd=["docker","run","--rm","--name",tester,"--network",RUN,"--label",f"pingap.canary={RUN}","-e",f"CASE={CASE}","-e",f"OPEN={int(open_mode)}","-v",f"{OUT}/client.js:/client.js:ro","-v",f"{OUT}:/coord","node:24-alpine","node","/client.js"]
        with (OUT/("client-open.log" if open_mode else "client.log")).open('w') as log:
            process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
            if CASE=="policy-unavailable-limit":
                for signal,bad,done in [('ready-limit',True,'reload-bad'),('refused-limit',False,'reload-fixed')]:
                    deadline=time.monotonic()+60
                    while not (OUT/signal).exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.1)
                    if not (OUT/signal).exists():raise RuntimeError('missing limit reload coordination')
                    (CONF/'pingap.toml').write_text(configuration(open_mode,edited=bad))
                    time.sleep(15)
                    (OUT/done).write_text('ready')
            if CASE=="native-scenario":
                for signal in ("ready","retained","reset"):
                    deadline=time.monotonic()+50
                    while not (OUT/signal).exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.1)
                    if not (OUT/signal).exists():raise RuntimeError(f"missing {signal} coordination")
                    text=configuration(edited=signal!="ready",unrelated=True)
                    if signal=="reset":
                        start=text.index('[plugins."behaviour:reload"]')
                        end=text.index('[plugins."behaviour:broken"]',start)
                        text+=text[start:end].replace('[plugins."behaviour:reload"','[plugins."behaviour:duplicate"')
                    (CONF/"pingap.toml").write_text(text+f"\n# reload {signal}\n")
                    time.sleep(15)
                    (OUT/({"ready":"unrelated","retained":"edited","reset":"duplicate"}[signal])).write_text("ready")
            if process.wait(timeout=100)!=0:raise RuntimeError("native client failed; inspect isolated client log")
        logs=docker("logs",candidate,check=False)
        # Docker application logger can use stderr.
        log_run=subprocess.run(["docker","logs",candidate],capture_output=True,text=True)
        (OUT/("candidate-open.log" if open_mode else "candidate.log")).write_text(log_run.stdout+log_run.stderr)
        if open_mode and "serving unprotected" not in log_run.stdout+log_run.stderr:raise RuntimeError("missing explicit fail_open warning")
        (OUT/("state-open.json" if open_mode else "state.json")).write_text(docker("inspect",candidate,"--format","{{json .State}}"))
        docker("rm","-f",candidate);owned.remove(candidate)
    after=services();expected=sorted(line for line in after if not any(f" {name} " in line for name in owned))
    (OUT/"services-after.json").write_text(json.dumps(expected))
    if expected!=before:raise RuntimeError("unrelated service inventory changed")
    print("NATIVE_SCENARIO_PASS" if CASE=="native-scenario" else "POLICY_UNAVAILABLE_LIMIT_PASS" if CASE=="policy-unavailable-limit" else "POLICY_UNAVAILABLE_BEHAVIOUR_PASS")
finally:
    for name in reversed(owned):
        label=docker("inspect",name,"--format",'{{index .Config.Labels "pingap.canary"}}',check=False)
        if label==RUN:
            logs=subprocess.run(["docker","logs",name],capture_output=True,text=True)
            (OUT/(name+".log")).write_text(logs.stdout+logs.stderr)
            docker("rm","-f",name,check=False)
    if docker("network","inspect",RUN,"--format",'{{index .Labels "pingap.canary"}}',check=False)==RUN:docker("network","rm",RUN,check=False)
