'use strict';
const $ = id => document.getElementById(id);
const ns = 'http://www.w3.org/2000/svg';
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const pause = ms => new Promise(resolve=>setTimeout(resolve,reduced?20:ms));
function svgNode(tag,attrs={},text){const el=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))el.setAttribute(k,v);if(text!==undefined)el.textContent=text;return el;}

// A deterministic visual maze. Its route illustrates milestones, not quantum search.
function layout(){
 const cols=12,rows=7,seen=new Set([0]),edges=new Set(),stack=[0];let seed=73;
 const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
 const edge=(a,b)=>[a,b].sort((x,y)=>x-y).join('-');
 const neighbors=i=>[i%cols?i-1:-1,i%cols<cols-1?i+1:-1,i>=cols?i-cols:-1,i<cols*(rows-1)?i+cols:-1].filter(x=>x>=0);
 while(stack.length){const i=stack.at(-1),opts=neighbors(i).filter(j=>!seen.has(j));if(!opts.length){stack.pop();continue;}const j=opts[Math.floor(rand()*opts.length)];seen.add(j);edges.add(edge(i,j));stack.push(j);}
 const start=cols*3,end=cols*3+cols-1,parents=new Map([[start,null]]),queue=[start];
 for(let h=0;h<queue.length;h++){const i=queue[h];for(const j of neighbors(i))if(edges.has(edge(i,j))&&!parents.has(j)){parents.set(j,i);queue.push(j);}}
 let i=end,route=[];while(i!==null){route.push(i);i=parents.get(i);}route.reverse();
 return {cols,rows,edges,edge,route};
}
const grid=layout();
function maze(id){
 const svg=svgNode('svg',{viewBox:'0 0 560 286','aria-hidden':'true'}),cell=36,ox=24,oy=12;
 const coords=i=>[ox+(i%grid.cols)*cell+cell/2,oy+Math.floor(i/grid.cols)*cell+cell/2];
 let walls='';for(let r=0;r<grid.rows;r++)for(let c=0;c<grid.cols;c++){
  const x=ox+c*cell,y=oy+r*cell,i=r*grid.cols+c;
  if(r===0)walls+=`M${x},${y}h${cell}`;
  if(c===0&&r!==3)walls+=`M${x},${y}v${cell}`;
  if(r===grid.rows-1||!grid.edges.has(grid.edge(i,i+grid.cols)))walls+=`M${x},${y+cell}h${cell}`;
  if((c===grid.cols-1&&r!==3)||(c<grid.cols-1&&!grid.edges.has(grid.edge(i,i+1))))walls+=`M${x+cell},${y}v${cell}`;
 }
 svg.append(svgNode('path',{d:walls,class:'wall'}));
 const points=[[4,138],...grid.route.map(coords),[508,138]],d=points.map((p,i)=>(i?'L':'M')+p.join(',')).join(' ');
 svg.append(svgNode('path',{d,class:'ghost-path'}));
 const trail=svgNode('path',{d,class:'trail'});svg.append(trail);
 const gate=svgNode('path',{d:'M22,126v24',class:'gate'});svg.append(gate);
 const box=svgNode('rect',{x:480,y:110,width:56,height:56,rx:12,class:'vault-box'});
 svg.append(box,svgNode('circle',{cx:508,cy:138,r:15,class:'vault-ring'}),svgNode('path',{d:'M501,143v-9h14v9z M504,134v-4a4,4 0 0 1 8,0v4',class:'vault-icon'}));
 const outcome=svgNode('g',{class:'outcome'});outcome.append(svgNode('rect',{x:480,y:110,width:56,height:56,rx:12,fill:'#291a20'}),svgNode('text',{x:508,y:151},'×'));svg.append(outcome);
 svg.append(svgNode('text',{x:476,y:186,class:'map-label'},'VAULT'),svgNode('text',{x:24,y:280,class:'map-label'},'SCHEMATIC / NOT THE ALGORITHM’S SEARCH SPACE'));
 const packet=svgNode('circle',{cx:4,cy:138,r:5,class:'packet'});svg.append(packet);
 $(id).replaceChildren(svg);const length=trail.getTotalLength();trail.setAttribute('stroke-dasharray',length);trail.setAttribute('stroke-dashoffset',length);
 let progress=0;
 function set(t){progress=t;trail.setAttribute('stroke-dashoffset',length*(1-t));const p=trail.getPointAtLength(length*t);packet.setAttribute('cx',p.x);packet.setAttribute('cy',p.y);}
 return {set,async move(to,duration=800){const from=progress,start=performance.now();duration=reduced?1:duration;await new Promise(resolve=>{function frame(now){const t=Math.min(1,(now-start)/duration);set(from+(to-from)*t);if(t<1)requestAnimationFrame(frame);else resolve();}requestAnimationFrame(frame);});},stopPoint:18/length};
}
let maps={rsa:maze('rsa-maze'),pqc:maze('pqc-maze')},busy=false;
function status(side,text){$(side+'-status').textContent=text;}
function badge(side,text){$(side+'-badge').textContent=text;}
function result(side,icon,title,detail){const root=$(side+'-result');root.replaceChildren();const sym=document.createElement('span');sym.className='result-icon';sym.textContent=icon;const div=document.createElement('div'),strong=document.createElement('strong'),small=document.createElement('small');strong.textContent=title;small.textContent=detail;div.append(strong,small);root.append(sym,div);}
function log(side,code,output){const li=document.createElement('li'),c=document.createElement('code'),small=document.createElement('small');c.textContent=code;small.textContent=output;li.append(c,small);$(side+'-log').append(li);}
function step(n){for(let i=1;i<=3;i++)$('step-'+i).classList.toggle('active',i===n);}
function reset(){for(const side of ['rsa','pqc']){$(side+'-panel').className='vault';$(side+'-log').replaceChildren();maps[side].set(0);badge(side,'Encrypting');result(side,'◇','Encrypting a fresh flag…','Private keys stay on the local server.');} $('rsa-current').textContent='vault = seal(secret, public_key)';$('pqc-current').textContent='vault = seal(secret, public_key)';$('pqc-checks').replaceChildren();$('spectrum').replaceChildren();$('measurement').textContent='Available after the simulation.';}
async function requestRun(){const response=await fetch('/api/run',{method:'POST',signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error('The encryption engine could not complete this run. Restart the local lab and retry.');return response.json();}
function attack(publicKey,ciphertext){return new Promise((resolve,reject)=>{const worker=new Worker('worker.js');const timer=setTimeout(()=>{worker.terminate();reject(new Error('Simulation timed out. Please try a new run.'));},20000);const finish=()=>{clearTimeout(timer);worker.terminate();};worker.onmessage=({data})=>{finish();data.ok?resolve(data):reject(new Error(data.error));};worker.onerror=()=>{finish();reject(new Error('The simulation worker failed. Please reload and retry.'));};worker.postMessage({public:publicKey,ciphertext});});}
async function hashHex(hex){const bytes=Uint8Array.from(hex.match(/../g)||[],h=>parseInt(h,16));return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');}
function spectrum(prob,c){const svg=$('spectrum'),max=Math.max(...prob),bins=125;let bars='';for(let i=0;i<bins;i++){const group=prob.slice(Math.floor(i*prob.length/bins),Math.floor((i+1)*prob.length/bins));const height=Math.max(...group)/max*85;bars+=`M${i*4},98v-${height.toFixed(2)}`;}svg.append(svgNode('path',{d:bars,stroke:'#b7a1f6','stroke-width':2}));svg.append(svgNode('line',{x1:c/prob.length*500,x2:c/prob.length*500,y1:0,y2:100,stroke:'#ff7e87'}));}
async function run(){if(busy)return;busy=true;$('run').disabled=true;$('run').textContent='Experiment running…';$('error').hidden=true;reset();step(1);
 try{
  status('rsa','Generating the flag and encrypting it with toy RSA.');status('pqc','Generating a new ML-KEM key pair and encrypting the same flag.');
  const data=await requestRun();$('run-id').textContent='RUN '+data.run_id.toUpperCase();$('connection').textContent='Live local encryption · fresh challenge';
  for(const side of ['rsa','pqc']){$(side+'-source').textContent=data[side].source;for(const event of data[side].events)log(side,event.code,event.output+' · '+event.ms+' ms');badge(side,'Sealed');result(side,'◇','Flag encrypted','Only public information is available to the attacker.');}
  $('vault-source').textContent=data.vault_source;
  log('rsa','public_key = (n, e)',`n = ${data.rsa.public.n} · e = ${data.rsa.public.e}`);
  log('rsa','vault.ciphertext',data.rsa.ciphertext);
  log('pqc','vault.ciphertext',data.pqc.ciphertext.slice(0,170)+'…');
  await pause(800);step(2);
  status('rsa','Shor’s simulation looks for a repeating pattern in modular arithmetic.');badge('rsa','Simulating');
  status('pqc','Checking whether this RSA factoring attack applies to the new key.');badge('pqc','Checking');
  // Worker receives no expected plaintext, digest, factors, or private exponent.
  $('rsa-current').textContent='QC.crackRSA(publicKey, ciphertext)';$('pqc-current').textContent='run_quantum_attack(vault, public_key)';
  const attackPromise=attack(data.rsa.public,data.rsa.ciphertext);
  const settled=attackPromise.then(value=>({value}),error=>({error}));
  await Promise.all([maps.rsa.move(.25,1000),maps.pqc.move(maps.pqc.stopPoint,1000)]);
  const outcome=await settled;if(outcome.error)throw outcome.error;const r=outcome.value;
  const digest=await hashHex(r.bytesHex);if(digest!==data.secret_sha256)throw new Error('Recovered bytes did not match the sealed flag. No breach result shown.');
  const p=data.pqc,checks=p.checks;
  // Validate the actual server-issued key and typed dispatch result; absence of n alone is not security evidence.
  if(p.algorithm!=='ml-kem-768'||p.public.level!=='768'||atob(p.public.ek).length!==1184||p.attack.applicable!==false||p.attack.probe.public_key_bytes!==1184||!Object.values(checks).every(v=>v===true))throw new Error('Post-quantum verification did not pass.');
  log('rsa','QC.crackRSA(publicKey, ciphertext)',`${r.attempts.length} period-finding attempt(s) · ${r.ms.toFixed(1)} ms computation`);
  for(const [i,a]of r.attempts.entries())log('rsa',`quantum_period_finding(a=${a.a}, N=${a.N})`,`Attempt ${i+1}: measured ${a.measuredC}/${a.M}; candidate period ${a.period??'none'}${i===r.attempts.length-1?' → usable factors':' → retry'}`);
  spectrum(r.distribution,r.pf.measuredC);$('measurement').textContent=`Actual Born probabilities · base ${r.pf.a} · measurement ${r.pf.measuredC}/${r.pf.M}. Ideal simulation, not physical hardware.`;
  status('rsa',`Pattern found. Period ${r.pf.period} lets the attacker factor ${data.rsa.public.n} = ${r.factors.join(' × ')}.`);
  log('rsa','d = inverse(e, (p - 1) * (q - 1))',`Recovered private exponent d = ${r.d}`);
  status('pqc','Shor not applicable. This key is not an RSA factoring target.');badge('pqc','Not applicable');$('pqc-panel').classList.add('protected');
  result('pqc','✓','Flag stays encrypted','This RSA attack does not apply. Owner access and tamper checks passed.');
  log('pqc','run_quantum_attack(vault, keys.public)','applicable = False · quantum simulation not executed');
  for(const [key,label]of Object.entries({owner_roundtrip:'Owner key recovered the original bytes',tamper_rejected:'Altered ciphertext was rejected',wrong_key_rejected:'Unrelated private key was rejected'})){const el=document.createElement('p');el.textContent='✓ '+label;$('pqc-checks').append(el);log('pqc',key,String(checks[key]));}
  await maps.rsa.move(.68,1400);status('rsa','The recovered private key now decrypts the vault.');await maps.rsa.move(1,1200);
  $('rsa-current').textContent='rsaDecryptBytes(ciphertext, recovered_d, n)';$('pqc-current').textContent='attack.applicable == False';
  log('rsa','rsaDecryptBytes(ciphertext, recovered_d, n)','SHA-256(recovered bytes) matches the server commitment');
  $('rsa-panel').classList.add('breached');badge('rsa','Breached');result('rsa','⚑',r.plaintext,'Flag recovered from ciphertext · digest verified');
  status('rsa','Vault breached. The red flag is the secret the attacker actually recovered.');step(3);$('connection').textContent='Complete · both results verified for this run';
 }catch(error){$('error').textContent=error.message;$('error').hidden=false;$('connection').textContent='Run incomplete · retry when ready';for(const side of ['rsa','pqc'])if(!$(side+'-panel').classList.contains('protected')&&!$(side+'-panel').classList.contains('breached')){badge(side,'Incomplete');status(side,'This run could not be completed. See the message above.');result(side,'!','No verified result','Retry to generate a new challenge.');}}
 finally{busy=false;$('run').disabled=false;$('run').textContent='Run a new experiment ↗';}
}
$('run').addEventListener('click',run);
(async()=>{try{const r=await fetch('/api/health',{signal:AbortSignal.timeout(4000)});const data=await r.json();if(data.service!=='pqc-lab')throw new Error();$('run').textContent='Run the experiment ↗';$('run').disabled=false;$('connection').textContent='Live local encryption · about 6 seconds';}catch{$('connection').textContent='Local engine needed · start with make web';$('run').textContent='Retry connection';$('run').disabled=false;$('run').onclick=()=>location.reload();$('run').removeEventListener('click',run);}})();
