/* COE576 offline teaching model. Not a networking stack or production crypto library.
 * Original ChaCha20 (64-bit counter / 64-bit nonce), SSH split header/body keys,
 * sequence-number nonce, and Poly1305 over encrypted length + encrypted body.
 * Packet boundaries, session keys and handshake events are supplied by the model.
 */
(function (root) {
  'use strict';
  const enc = new TextEncoder();
  const bytes = x => typeof x === 'string' ? enc.encode(x) : new Uint8Array(x);
  const concat = (...xs) => { const out = new Uint8Array(xs.reduce((n,x)=>n+x.length,0)); let o=0; for(const x of xs){out.set(x,o);o+=x.length;} return out; };
  const hex = x => Array.from(x,b=>b.toString(16).padStart(2,'0')).join('');
  const unhex = s => new Uint8Array(s.match(/../g).map(v=>parseInt(v,16)));
  const be32 = n => new Uint8Array([n>>>24,n>>>16,n>>>8,n]);
  const string = s => {s=bytes(s);return concat(be32(s.length),s);};
  const equal = (a,b) => {if(a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a[i]^b[i];return x===0;};
  const rot = (n,k) => ((n<<k)|(n>>>(32-k)))>>>0;
  function quarter(x,a,b,c,d){
    x[a]=(x[a]+x[b])>>>0;x[d]=rot(x[d]^x[a],16);
    x[c]=(x[c]+x[d])>>>0;x[b]=rot(x[b]^x[c],12);
    x[a]=(x[a]+x[b])>>>0;x[d]=rot(x[d]^x[a],8);
    x[c]=(x[c]+x[d])>>>0;x[b]=rot(x[b]^x[c],7);
  }
  function stream(key,seq,counter,data){
    if(key.length!==32)throw Error('ChaCha20 requires a 32-byte key.');
    const initial=new Uint32Array(16),v=new DataView(key.buffer,key.byteOffset,key.byteLength);
    initial.set([0x61707865,0x3320646e,0x79622d32,0x6b206574]);
    for(let i=0;i<8;i++)initial[4+i]=v.getUint32(i*4,true);
    initial[12]=counter>>>0;initial[13]=Math.floor(counter/4294967296)>>>0;
    const nonce=concat(new Uint8Array(4),be32(seq>>>0));
    const nv=new DataView(nonce.buffer);initial[14]=nv.getUint32(0,true);initial[15]=nv.getUint32(4,true);
    const out=new Uint8Array(data.length);
    for(let off=0;off<data.length;off+=64){
      const x=new Uint32Array(initial);
      for(let r=0;r<10;r++){
        quarter(x,0,4,8,12);quarter(x,1,5,9,13);quarter(x,2,6,10,14);quarter(x,3,7,11,15);
        quarter(x,0,5,10,15);quarter(x,1,6,11,12);quarter(x,2,7,8,13);quarter(x,3,4,9,14);
      }
      const block=new Uint8Array(64),bv=new DataView(block.buffer);
      for(let j=0;j<16;j++)bv.setUint32(j*4,(x[j]+initial[j])>>>0,true);
      for(let j=0;j<64 && off+j<data.length;j++)out[off+j]=data[off+j]^block[j];
      initial[12]=(initial[12]+1)>>>0;if(initial[12]===0)initial[13]=(initial[13]+1)>>>0;
    }
    return out;
  }
  function little(x){let n=0n;for(let i=x.length-1;i>=0;i--)n=(n<<8n)+BigInt(x[i]);return n;}
  function poly1305(key,data){
    const r=little(key.slice(0,16))&0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s=little(key.slice(16,32)),p=(1n<<130n)-5n;let a=0n;
    for(let i=0;i<data.length;i+=16){const b=data.slice(i,i+16);a=((a+little(b)+(1n<<BigInt(8*b.length)))*r)%p;}
    let tag=(a+s)&((1n<<128n)-1n);const out=new Uint8Array(16);
    for(let i=0;i<16;i++){out[i]=Number(tag&255n);tag>>=8n;}return out;
  }
  function generator(seed){let n=(seed>>>0)||0x9e3779b9;return count=>{const out=new Uint8Array(count);for(let i=0;i<count;i++){n^=n<<13;n^=n>>>17;n^=n<<5;out[i]=n&255;}return out;};}
  function seal(key,payload,seq,rng){
    if(key.length!==64)throw Error('SSH model requires 64 key bytes.');
    let pad=8-((1+payload.length)%8);if(pad<4)pad+=8;
    const body=concat(new Uint8Array([pad]),payload,rng(pad));
    const main=key.slice(0,32),header=key.slice(32);
    const wire=concat(stream(header,seq,0,be32(body.length)),stream(main,seq,1,body));
    return concat(wire,poly1305(stream(main,seq,0,new Uint8Array(32)),wire));
  }
  function open(key,wire,seq){
    if(wire.length<24)return {ok:false,reason:'Packet too short',attached:'',computed:''};
    const ct=wire.slice(0,-16),tag=wire.slice(-16),main=key.slice(0,32);
    const computed=poly1305(stream(main,seq,0,new Uint8Array(32)),ct);
    const evidence={attached:hex(tag),computed:hex(computed),ciphertext:hex(ct)};
    if(!equal(tag,computed))return {...evidence,ok:false,reason:'Authentication tag mismatch'};
    const lb=stream(key.slice(32),seq,0,ct.slice(0,4));
    const length=new DataView(lb.buffer).getUint32(0,false);
    if(length!==ct.length-4||length%8!==0)return {...evidence,ok:false,reason:'Invalid packet length'};
    const body=stream(main,seq,1,ct.slice(4)),pad=body[0];
    if(pad<4||pad+1>=body.length)return {...evidence,ok:false,reason:'Invalid padding'};
    return {...evidence,ok:true,payload:body.slice(1,-pad),reason:'Tag and framing verified'};
  }
  function messages(){return [concat(new Uint8Array([7]),be32(1),string('ping@openssh.com'),string('0')),concat(new Uint8Array([6]),string('ssh-userauth')),...Array.from({length:10},()=>concat(new Uint8Array([2]),string('offline filler')))];}
  const presets=[
    {id:'clean',name:'1. Clean legacy',i:0,d:0,mode:'legacy',tamper:false},
    {id:'drop',name:'2. Drop only',i:0,d:1,mode:'legacy',tamper:false},
    {id:'inject',name:'3. Inject only',i:1,d:0,mode:'legacy',tamper:false},
    {id:'matched',name:'4. Matched truncation',i:1,d:1,mode:'legacy',tamper:false},
    {id:'reset',name:'5. Reset counters only',i:1,d:1,mode:'reset',tamper:false},
    {id:'reject',name:'6. Reject optional only',i:1,d:1,mode:'reject',tamper:false},
    {id:'strict',name:'7. Strict KEX model',i:1,d:1,mode:'strict',tamper:false},
    {id:'tamper',name:'8. Tampered ciphertext',i:1,d:1,mode:'legacy',tamper:true},
    {id:'clean-strict',name:'9. Clean strict KEX',i:0,d:0,mode:'strict',tamper:false}
  ];
  function simulate(options={}){
    const o={i:1,d:1,mode:'legacy',tamper:false,seed:57611,...options};
    if(!Number.isInteger(o.i)||!Number.isInteger(o.d)||o.i<0||o.i>8||o.d<0||o.d>8||!['legacy','reset','reject','strict'].includes(o.mode))throw Error('Invalid scenario');
    const reset=['reset','strict'].includes(o.mode),reject=['reject','strict'].includes(o.mode);
    const rng=generator(o.seed),key=rng(64),payloads=messages();
    let cs=0,cr=0,ss=0,sr=0,accepted=0,dropped=0,injected=0,ext='Not sent',phase='Handshake';
    const states=Array(12).fill('pending'),trace=[],packets=[];
    function snap(title,detail,kind='normal',direction='none',extra={}){
      trace.push({title,detail,kind,direction,cs,cr,ss,sr,accepted,dropped,injected,ext,phase,states:[...states],...extra});
    }
    function finish(ok,status){
      const result={accepted:ok,prefix_removed:ok&&dropped>0,ext_missing:ok&&ext==='Dropped',status,received:accepted,actual_dropped:dropped,actual_injected:injected};
      const title=ok?(dropped?'Accepted suffix; prefix missing':'Accepted complete stream'):'Rejected';
      const detail=ok?(dropped?`${accepted} genuine packets passed. ${dropped} initial packet(s) are missing. This does not establish a usable login or a real feature downgrade.`:'All 12 protected packets passed. No deletion occurred; this is not attack success.'):(status==='handshake_rejected'?'The receiver stopped at the unexpected handshake message. The planned encrypted deletion was never reached.':'The receiver stopped at its first failed packet check. No later packets are processed.');
      phase='Finished';snap(title,detail,ok?(dropped?'attack-success':'success'):'rejected','none',{result});
      return {options:o,trace,result,packets};
    }
    snap('Ready to start','Follow server Snd and client Rcv for the attacked server-to-client direction. Numbers are the next packet numbers after each event.');
    snap('Exchange version strings','Version strings are not SSH binary packets, so these counters stay at zero.','normal','both');
    cs++;cr++;ss++;sr++;snap('KEXINIT: algorithm choices','Each endpoint sends and receives one binary packet. The teaching model selects the SSH ChaCha20-Poly1305 construction.','normal','both');
    cs++;sr++;snap('KEXDH_INIT: client contribution','The client sends its public Diffie-Hellman contribution. Key exchange is schematic here: a shared test key is supplied to the packet model.','normal','client-server');
    ss++;cr++;snap('KEXDH_REPLY: server contribution','The real exchange carries the server contribution, host key and signature. This model assumes correct server authentication; it does not implement that verification.','normal','server-client');
    for(let j=0;j<o.i;j++){
      if(reject){snap('Unexpected IGNORE rejected','The negotiated safeguard refuses this optional handshake message before accepting it. The connection aborts.','rejected','attacker-client');return finish(false,'handshake_rejected');}
      cr++;injected++;snap(`Inject IGNORE ${j+1} of ${o.i}`,'The client counts an extra packet. The server sent nothing, so its Snd stays unchanged.','injected','attacker-client');
    }
    ss++;cr++;if(reset){ss=0;cr=0;}
    snap('Server NEWKEYS',reset?'Server Snd and client Rcv reset to zero. The injected offset is erased in this direction.':'Server-to-client encryption becomes active. Legacy counters keep their values, including any injected offset.','newkeys','server-client');
    cs++;sr++;if(reset){cs=0;sr=0;}phase='Encrypted packets';
    snap('Client NEWKEYS',reset?'Client Snd and server Rcv also reset. Both directions now use the new test keys.':'Client-to-server encryption becomes active. No legacy counter is reset.','newkeys','client-server');
    for(let j=0;j<12;j++){
      if(j===1){cs++;sr++;snap('SERVICE_REQUEST: ssh-userauth','This request travels in the other direction. It changes client Snd and server Rcv, not the attacked pair. Its transport is schematic in this one-direction packet model.','normal','client-server');}
      const seq=ss;let wire=seal(key,payloads[j],seq,rng);ss++;
      const name=j===0?'EXT_INFO':j===1?'SERVICE_ACCEPT':`Filler ${j-1}`;
      if(j<o.d){
        dropped++;states[j]='dropped';if(j===0)ext='Dropped';
        packets.push({index:j,name,seq,wire:hex(wire),status:'dropped'});
        snap(`Delete ${name} (packet #${seq})`,'The server counts the packet it sent. The client receives nothing and does not advance.','dropped','server-attacker',{packet:j,sentSeq:seq,expectedSeq:cr});continue;
      }
      let tampered=false;if(o.tamper&&j===o.d){wire=wire.slice();wire[5]^=1;tampered=true;}
      const expected=cr,check=open(key,wire,expected);
      if(check.ok&&!equal(check.payload,payloads[j])){check.ok=false;check.reason='Recovered payload differs from the expected suffix';}
      const evidence={attached:check.attached,computed:check.computed,ciphertext:check.ciphertext,ok:check.ok,reason:check.reason,sentSeq:seq,expectedSeq:expected,tampered};
      states[j]=check.ok?'accepted':'rejected';packets.push({index:j,name,seq,wire:hex(wire),status:states[j]});
      if(check.ok){accepted++;cr++;if(j===0)ext='Received';}
      else if(j===0)ext='Rejected';
      snap(`${name}: ${check.ok?'tag verified':'check failed'}`,check.ok?`Sender used #${seq}; receiver expected #${expected}. The actual tag and decrypted contents pass.`:(tampered?(seq===expected?'A ciphertext bit was changed. Even with matching counters, the original authentication tag no longer verifies.':`A ciphertext bit was changed, and the counters also differ: sender #${seq}, receiver #${expected}. Verification fails.`):`Sender used #${seq}; receiver expected #${expected}. Their different packet numbers produce different authentication keys.`),check.ok?'verified':'rejected','server-client',{packet:j,check:evidence});
      if(!check.ok)return finish(false,'packet_rejected');
    }
    return finish(true,'accepted');
  }
  const api={stream,poly1305,seal,open,messages,generator,hex,unhex,bytes,presets,simulate};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;
  else root.Terrapin=api;
})(typeof globalThis!=='undefined'?globalThis:this);

