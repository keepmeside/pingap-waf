const fs=require('fs'),http=require('http'),crypto=require('crypto');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
function check(value,label){if(!value)throw Error(label)}
async function call(port,path,method='GET',body=null,auth=null,host=null,cookie=null){
 const data=body===null?null:JSON.stringify(body);return new Promise((resolve,reject)=>{
  const headers={};if(data){headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(data)}if(auth)headers.Authorization='Bearer '+auth;if(host)headers.Host=host;if(cookie)headers.Cookie=cookie;
  const request=http.request({hostname:'candidate',port,path,method,headers},response=>{let text='';response.on('data',c=>text+=c);response.on('end',()=>{let json=null;try{json=JSON.parse(text)}catch{}resolve({status:response.statusCode,json,text,headers:response.headers})})});request.on('error',reject);request.setTimeout(20000,()=>request.destroy(Error('request timeout '+method+' '+path.split('?')[0])));request.end(data);
 });
}
let token;const api=(path,method='GET',body=null)=>call(3018,'/api'+path,method,body,token);
const traffic=(host='site.test',cookie=null,path='/')=>call(8080,path,'GET',null,null,host,cookie);
async function ready(){for(let i=0;i<200;i++){try{if((await call(3018,'/api/health')).status===200)return}catch{}await pause(100)}throw Error('candidate readiness')}
async function eventually(fn,label){for(let i=0;i<900;i++){if(await fn())return;await pause(100)}throw Error(label)}
async function waitSignal(name){for(let i=0;i<900&&!fs.existsSync('/out/'+name);i++)await pause(100);check(fs.existsSync('/out/'+name),'missing signal '+name);await ready()}
async function put(path,body){const started=Date.now();const response=await api(path,'PUT',body);console.log('APPLY',path,response.status,Date.now()-started);check(response.status===200&&response.json.status==='applied','apply '+path+' status='+response.status);return response.json}
async function solved(){const response=await traffic();check(response.text.includes('Checking your browser'),'real challenge issue');
 const value=name=>{const match=response.text.match(new RegExp('name="'+name+'" value="([^"]*)"'));check(match,'form '+name);return match[1]};
 const challenge=value('challenge_token'),salt=value('challenge_salt'),difficulty=Number(value('challenge_difficulty'));
 let nonce=0;for(;nonce<1000000;nonce++){const digest=crypto.createHash('sha256').update(salt+nonce).digest();const full=Math.floor(difficulty/8),remaining=difficulty%8;if(digest.subarray(0,full).every(byte=>byte===0)&&(!remaining||digest[full]>>(8-remaining)===0))break}
 check(nonce<1000000,'real proof work');const verified=await traffic('site.test',null,'/.pingap/challenge/verify?challenge_token='+encodeURIComponent(challenge)+'&nonce='+nonce);
 check(verified.status===303,'real proof verification');const cookie=(verified.headers['set-cookie']||[]).find(c=>c.startsWith('pingap_challenge='))?.split(';')[0];check(cookie,'pass cookie');
 check((await traffic('site.test',cookie)).text==='fixture','issued pass reaches upstream');return cookie;
}
(async()=>{
 await ready();const login=await api('/auth/login','POST',{username:'canary-admin',password:process.env.PASSWORD});check(login.status===200,'login');token=login.json.token;
 await put('/upstreams/app',{backends:[{addr:'fixture:8081',weight:null}],lb_algorithm:null,health_check:null,discovery:null,tls_sni:null,verify_cert:null});
 await put('/listeners/http',{addr:'0.0.0.0:8080',http2:null,tls:null,access_log:null,server_timing:null});
 await put('/policies/acl:verify',{category:'acl',rules:[{field:'method',operator:'equals',values:['GET'],action:'challenge'}]});
 const profile=reference=>({category:'challenge',enabled:true,secret_file:reference,client_ip_from_peer:true,kind:'pow',difficulty:1,loop_threshold:100,remark:'retained'});
 const legacy=key=>{const conf=profile('challenge-v1');delete conf.secret_file;conf.secret=key;return conf};
 await put('/policies/challenge:verify',legacy(process.env.LEGACY_KEY_ONE));
 const legacyView=await api('/policies/challenge:verify');check(!('secret' in legacyView.json)&&legacyView.json.secret_source.kind==='literal','legacy inspection redacted');
 await put('/policies/challenge:verify',legacy(process.env.LEGACY_KEY_TWO));
 // The preceding mutation changes only the literal key: it must still reload.
 await put('/policies/challenge:verify',{config:profile('challenge-v1')});
 for(const host of ['site','other','control'])await put('/domains/'+host,{hostnames:[host+'.test'],listener:'http',upstream:'app',grpc_web:false,policies:host==='control'?[]:[{acl:'verify'},{challenge:'verify'}]});
 const versions1=(await api('/config-versions')).json;const v1=versions1.find(v=>v.status==='applied');check(v1,'v1 applied');
 const pass1=await solved();check((await traffic('other.test',pass1)).text.includes('Checking your browser'),'cross-domain cookie refused');
 const inspect=await api('/policies/challenge:verify');check(inspect.json.secret_configured===true&&inspect.json.secret_source.kind==='file'&&!('secret' in inspect.json),'inspection source only');
 const same=await put('/policies/challenge:verify',{config:{...inspect.json,remark:'retained-edit'}});check(same.status==='applied','unchanged source edit');
 fs.writeFileSync('/out/restart-v1','ready');await waitSignal('restarted-v1');
 check((await traffic('site.test',pass1)).text==='fixture','pass v1 survives actual process restart');
 const afterRestart=(await api('/config-versions')).json;check(afterRestart.some(v=>v.id===same.version_id&&v.status==='applied'&&v.hash===same.hash),'restart ordinary hash reconciliation');
 // Crash the disposable candidate after the persisted version is actually pending.
 // Never retry an interrupted mutation before reading that version's outcome.
 const changing=api('/policies/challenge:verify','PUT',{config:profile('challenge-v2')}).catch(()=>null);
 let pendingVersion;
 await eventually(async()=>{const versions=await api('/config-versions');pendingVersion=versions.json?.find(v=>v.status==='pending');return !!pendingVersion},'persisted pending file-backed version');
 fs.writeFileSync('/out/restart-pending','ready');await waitSignal('restarted-pending');
 const interrupted=await changing;check(!interrupted||interrupted.status!==200,'pending write interrupted by process crash');
 await eventually(async()=>{const rows=(await api('/config-versions')).json;return rows?.some(v=>v.id===pendingVersion.id&&v.status==='applied'&&v.hash===pendingVersion.hash)},'pending version reconciles with ordinary runtime key');
 check((await traffic('site.test',pass1)).text.includes('Checking your browser'),'v2 rejects old pass');const pass2=await solved();
 const rollback=await api('/config-versions/'+v1.id+'/rollback','POST',{});check(rollback.status===200&&rollback.json.version.status==='applied','rollback v1 applied');
 check((await traffic('site.test',pass1)).text==='fixture','rollback accepts v1');check((await traffic('site.test',pass2)).text.includes('Checking your browser'),'rollback rejects v2');
 await put('/policies/challenge:verify',{config:profile('challenge-v2')});
 fs.writeFileSync('/out/remove-v1','ready');await waitSignal('removed-v1');
 const rejected=await api('/config-versions/'+v1.id+'/rollback','POST',{});check(rejected.status===200&&rejected.json?.version.status==='failed'&&rejected.json.version.error?.includes('secret_file'),'missing old source rollback records failed version');
 check((await traffic('site.test',pass2)).text==='fixture','failed rollback leaves current v2 live');check((await traffic('control.test')).text==='fixture','control unaffected');
 fs.writeFileSync('/out/result.json',JSON.stringify({real_proof:true,legacy_rotation_applied:true,debug_logs_redacted:true,restart:true,ordinary_hash:true,pending_crash_reconciliation:true,rotation:true,rollback:true,missing_old_file_refused:true,cross_domain:true,control:true}));
 console.log('CHALLENGE_SECRET_CLIENT_PASS');
})().catch(error=>{console.error(error.message);process.exitCode=1});
