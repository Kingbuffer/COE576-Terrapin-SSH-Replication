'use strict';
(() => {
  const $=id=>document.getElementById(id), E=window.Terrapin;
  let trial,index=0,timer=null,activeTab='demo',gridBusy=false,currentSeed=57611;
  const ns='http://www.w3.org/2000/svg';
  const modeNames={legacy:'Legacy',reset:'Reset only',reject:'Reject optional only',strict:'Strict KEX'};
  function options(){return {i:Number($('injections').value),d:Number($('deletions').value),mode:$('mode').value,tamper:$('tamper').checked,seed:currentSeed};}
  function stop(){if(timer!==null)clearTimeout(timer);timer=null;$('play').textContent='Play';}
  function selectTab(id){stop();activeTab=id;for(const b of document.querySelectorAll('[data-tab]')){const yes=b.dataset.tab===id;b.setAttribute('aria-selected',String(yes));$(b.getAttribute('aria-controls')).hidden=!yes;}if(id==='demo')drawArrow(trial.trace[index]);}
  function restart(){stop();trial=E.simulate(options());index=0;$('i-value').textContent=trial.options.i;$('d-value').textContent=trial.options.d;$('seed-label').textContent=currentSeed;render();}
  function preset(id){const p=E.presets.find(p=>p.id===id);if(!p)return;currentSeed=57611;$('scenario').value=id;$('injections').value=p.i;$('deletions').value=p.d;$('mode').value=p.mode;$('tamper').checked=p.tamper;restart();}
  function custom(){const o=options(),p=E.presets.find(p=>p.i===o.i&&p.d===o.d&&p.mode===o.mode&&p.tamper===o.tamper);$('scenario').value=p?p.id:'custom';restart();}
  function go(n){index=Math.max(0,Math.min(n,trial.trace.length-1));if(index===trial.trace.length-1)stop();render();}
  function tick(){if(index>=trial.trace.length-1){stop();return;}go(index+1);if(index<trial.trace.length-1){timer=setTimeout(tick,Number($('speed').value));$('play').textContent='Pause';}}
  function play(){if(timer!==null){stop();return;}if(index===trial.trace.length-1)go(0);timer=setTimeout(tick,Number($('speed').value));$('play').textContent='Pause';}
  function svg(tag,attrs,text){const el=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs||{}))el.setAttribute(k,v);if(text!==undefined)el.textContent=text;return el;}
  function drawArrow(t){
    const s=$('scene'),w=s.getBoundingClientRect().width||700;s.replaceChildren();s.setAttribute('viewBox',`0 0 ${w} 80`);
    const c=w/6,a=w/2,r=5*w/6;
    for(const x of [c,a,r])s.append(svg('line',{x1:x,y1:0,x2:x,y2:73,stroke:'#cbd9e3','stroke-dasharray':'3 5'}));
    if(t.direction==='none'){s.append(svg('text',{x:w/2,y:46,'text-anchor':'middle'},index===0?'Next step begins the exchange':'End of this experiment'));return;}
    const color=['injected','dropped'].includes(t.kind)?'#a34b06':t.kind==='rejected'?'#ac263a':'#155ba3';
    const defs=svg('defs'),marker=svg('marker',{id:'arrow-tip',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:7,markerHeight:7,orient:'auto-start-reverse'});
    marker.append(svg('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:color}));defs.append(marker);s.append(defs);
    let from=r,to=c;if(t.direction==='client-server'){from=c;to=r;}if(t.direction==='attacker-client'){from=a;to=c;}if(t.direction==='server-attacker'){from=r;to=a;}
    const attrs={x1:from,y1:33,x2:to,y2:33,stroke:color,'stroke-width':3,'marker-end':'url(#arrow-tip)',class:'flow-line'};
    if(t.direction==='both'){attrs.x1=c;attrs.x2=r;attrs['marker-start']='url(#arrow-tip)';}s.append(svg('line',attrs));
    if(t.kind==='dropped')s.append(svg('text',{x:a,y:63,'text-anchor':'middle',style:'fill:#a34b06;font-weight:700'},'Deleted here'));
    else s.append(svg('text',{x:w/2,y:64,'text-anchor':'middle'},t.direction==='attacker-client'?'Injected toward the client':t.direction==='client-server'?'Client → server':t.direction==='both'?'Both endpoints exchange messages':'Server → client'));
    s.setAttribute('aria-label',`${t.title}: ${t.direction.replaceAll('-',' to ')}`);
  }
  function render(){
    const t=trial.trace[index];$('step-title').textContent=t.title;$('explanation').textContent=t.detail;$('step-count').textContent=`Step ${index} / ${trial.trace.length-1}`;
    for(const k of ['cs','cr','ss','sr'])$(k).textContent=t[k];$('actual-i').textContent=t.injected;$('actual-d').textContent=t.dropped;
    const which=t.kind==='newkeys'?'keys':(t.phase==='Handshake'||t.result?.status==='handshake_rejected')?'handshake':'packets';
    for(const k of ['handshake','keys','packets'])$('phase-'+k).classList.toggle('active',which===k);
    $('back').disabled=index===0;$('next').disabled=index===trial.trace.length-1;$('finish').disabled=index===trial.trace.length-1;
    $('packets').replaceChildren();
    t.states.forEach((state,j)=>{
      const b=document.createElement('button');b.type='button';b.className=`packet ${state}`;b.disabled=state==='pending';
      const label=j===0?'EXT':j===1?'SVC':`F${j-1}`,full=j===0?'EXT_INFO':j===1?'SERVICE_ACCEPT':`Filler ${j-1}`;
      const strong=document.createElement('strong');strong.textContent=label;const small=document.createElement('small');small.textContent=state==='accepted'?'✓ verified':state==='dropped'?'− deleted':state==='rejected'?'× failed':'waiting';b.append(strong,small);b.setAttribute('aria-label',`${full}: ${state}`);b.title=`${full}: ${state}`;
      b.onclick=()=>{stop();const n=trial.trace.findIndex(x=>x.packet===j);if(n>=0)go(n);};$('packets').append(b);
    });
    const outcome=$('outcome');outcome.className='outcome'+(t.result?' '+t.kind:'');outcome.querySelector('strong').textContent=t.result?t.title:'In progress';
    $('facts').replaceChildren();for(const label of [`${t.accepted} verified`,`${t.dropped} deleted`,`EXT_INFO: ${t.ext.toLowerCase()}`]){const span=document.createElement('span');span.textContent=label;$('facts').append(span);}
    const checkStep=trial.trace.slice(0,index+1).reverse().find(x=>x.check);const body=$('tag-body');body.replaceChildren();
    if(!checkStep)body.textContent='Step to a retained encrypted packet to compare its attached tag with the receiver’s computed tag.';
    else{
      const z=checkStep.check,p=document.createElement('p');p.className='small';p.style.marginBottom='10px';p.textContent=`Most recent check: ${checkStep.title}. Sender number ${z.sentSeq}; receiver expected ${z.expectedSeq}. ${z.reason}.`;body.append(p);
      const g=document.createElement('div');g.className='tag-grid';for(const [label,value] of [['Attached tag',z.attached],['Receiver computed',z.computed],['Ciphertext',z.ciphertext]]){const l=document.createElement('strong');l.textContent=label;const v=document.createElement('code');v.textContent=value;g.append(l,v);}body.append(g);
      const note=document.createElement('p');note.className='small';note.style.marginTop='10px';note.textContent='Both tags are computed from actual packet bytes. Matching tags are followed by length, padding and expected-payload checks. Deleting an entire packet does not alter the tag on a surviving packet.';body.append(note);
    }
    $('event-log').replaceChildren();trial.trace.slice(1,index+1).forEach((x,n)=>{const tr=document.createElement('tr');if(n+1===index)tr.className='current';for(const text of [x.title,`${x.cs} / ${x.cr}`,`${x.ss} / ${x.sr}`]){const td=document.createElement('td');td.textContent=text;tr.append(td);}$('event-log').append(tr);});
    drawArrow(t);
  }
  function loadOptions(o){currentSeed=o.seed??57611;$('injections').value=o.i;$('deletions').value=o.d;$('mode').value=o.mode;$('tamper').checked=!!o.tamper;custom();selectTab('demo');}
  const descriptions={clean:'Complete stream; no attack',drop:'Uncompensated deletion',inject:'Counter offset remains',matched:'EXT_INFO missing from accepted suffix',reset:'Reset erased the offset',reject:'Handshake stopped before deletion',strict:'Handshake stopped before deletion',tamper:'Changed ciphertext fails verification','clean-strict':'Safeguards allow clean traffic'};
  function runControls(){
    $('controls-body').replaceChildren();let accepted=0;
    for(const [n,p] of E.presets.entries()){
      const r=E.simulate({...p,seed:57611+n}).result;if(r.accepted)accepted++;
      const tr=document.createElement('tr');const values=[p.name,`(${p.i}, ${p.d})`,null,`${r.received} / 12`,descriptions[p.id],null];
      values.forEach((text,k)=>{const td=document.createElement('td');if(k===2){const chip=document.createElement('span');chip.className='result-chip '+(r.prefix_removed?'attack':r.accepted?'yes':'no');chip.textContent=r.prefix_removed?'Accepted suffix':r.accepted?'Accepted clean':'Rejected';td.append(chip);}else if(k===5){const b=document.createElement('button');b.className='row-open';b.textContent='Show';b.onclick=()=>{preset(p.id);selectTab('demo');};td.append(b);}else td.textContent=text;tr.append(td);});$('controls-body').append(tr);
    }
    $('control-summary').textContent=`9 live trials completed: ${accepted} accepted, ${9-accepted} rejected. Two accepted cases are clean; one has prefix deletion.`;
  }
  function emptyGrid(){const g=$('count-grid');g.replaceChildren();g.append(document.createElement('span'));for(let d=0;d<9;d++){const n=document.createElement('span');n.className='axis-num';n.textContent=d;g.append(n);}for(let i=0;i<9;i++){const n=document.createElement('span');n.className='axis-num';n.textContent=i;g.append(n);for(let d=0;d<9;d++){const b=document.createElement('button');b.className='cell';b.disabled=true;b.textContent='·';b.id=`cell-${i}-${d}`;b.setAttribute('aria-label',`Inject ${i}, delete ${d}: not run`);g.append(b);}}}
  async function runGrid(){
    if(gridBusy)return;gridBusy=true;const mode=$('grid-mode').value;$('run-grid').disabled=true;$('grid-mode').disabled=true;emptyGrid();let passes=0;
    try{
      for(let i=0;i<9;i++){
        await new Promise(resolve=>setTimeout(resolve,0));
        for(let d=0;d<9;d++){
          const o={i,d,mode,tamper:false,seed:57611+i*9+d},r=E.simulate(o).result;if(r.accepted)passes++;
          const b=$(`cell-${i}-${d}`);b.disabled=false;b.className='cell '+(r.accepted?(i===0&&d===0?'clean':'pass'):'fail');b.textContent=r.accepted?'✓':'×';b.setAttribute('aria-label',`Inject ${i}, delete ${d}: ${r.accepted?'accepted':'rejected'}${i===0&&d===0?' (clean)':''}. Open walkthrough.`);b.onclick=()=>loadOptions(o);
        }
        $('grid-status').textContent=`${(i+1)*9} / 81 trials completed`;
      }
      $('grid-status').textContent=`${modeNames[mode]}: ${passes} accepted, ${81-passes} rejected. One trial per cell.`;
    }finally{gridBusy=false;$('run-grid').disabled=false;$('grid-mode').disabled=false;}
  }
  function selfTest(){
    const expected='76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586';
    if(E.hex(E.stream(new Uint8Array(32),0,0,new Uint8Array(64)))!==expected)throw Error('ChaCha20 self-test failed');
    const key=E.unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
    if(E.hex(E.poly1305(key,E.bytes('Cryptographic Forum Research Group')))!=='a8061dc1305136c6c22b8baf0c0127a9')throw Error('Poly1305 self-test failed');
    $('self-test').textContent='ChaCha20 + Poly1305 known-vector checks passed';
  }
  try{
    selfTest();for(const p of E.presets){const o=document.createElement('option');o.value=p.id;o.textContent=p.name;$('scenario').append(o);}const customOption=document.createElement('option');customOption.value='custom';customOption.textContent='Custom counts';customOption.disabled=true;$('scenario').append(customOption);
    $('scenario').onchange=()=>preset($('scenario').value);for(const k of ['injections','deletions'])$(k).oninput=custom;for(const k of ['mode','tamper'])$(k).onchange=custom;
    $('back').onclick=()=>{stop();go(index-1);};$('next').onclick=()=>{stop();go(index+1);};$('finish').onclick=()=>{stop();go(trial.trace.length-1);};$('restart').onclick=restart;$('play').onclick=play;
    for(const b of document.querySelectorAll('[data-tab]'))b.onclick=()=>selectTab(b.dataset.tab);
    for(const b of document.querySelectorAll('[data-preset]'))b.onclick=()=>{preset(b.dataset.preset);selectTab('demo');};
    $('run-controls').onclick=runControls;$('run-grid').onclick=runGrid;$('grid-mode').onchange=()=>{emptyGrid();$('grid-status').textContent='Safeguards changed. Run the grid again.';};
    $('export').onclick=()=>{
      const data={model:'Offline SSH-style ChaCha20-Poly1305 teaching model',scope:'Schematic handshake; real protected packet checks; no live SSH or feature downgrade measured',options:trial.options,result:trial.result,trace:trial.trace,packets:trial.packets};
      const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`terrapin-${trial.options.mode}-i${trial.options.i}-d${trial.options.d}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    };
    $('fullscreen').onclick=async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch(e){$('fullscreen').textContent='Use browser full screen (F11)';}};
    document.addEventListener('fullscreenchange',()=>{$('fullscreen').textContent=document.fullscreenElement?'Exit full screen':'Full screen';});
    document.addEventListener('keydown',e=>{if(activeTab!=='demo'||/INPUT|SELECT|TEXTAREA|BUTTON|SUMMARY/.test(e.target.tagName)||e.ctrlKey||e.metaKey||e.altKey)return;if(['ArrowRight','ArrowLeft',' ','r','R'].includes(e.key))e.preventDefault();if(e.key==='ArrowRight'){stop();go(index+1);}if(e.key==='ArrowLeft'){stop();go(index-1);}if(e.key===' ')play();if(e.key.toLowerCase()==='r')restart();});
    new ResizeObserver(()=>{if(trial&&activeTab==='demo')drawArrow(trial.trace[index]);}).observe($('scene'));
    emptyGrid();preset('matched');
  }catch(error){$('self-test').textContent=error.message;const box=document.createElement('div');box.className='fatal';box.textContent=`Simulator could not start: ${error.message}. Open this file in a current desktop browser.`;document.querySelector('main').prepend(box);document.querySelectorAll('button,input,select').forEach(e=>e.disabled=true);console.error(error);}
})();
