"""Independent packet checks: Python cryptography versus the JavaScript model.
Run: python3 source/verify.py   (requires Node.js and Python cryptography)
These tools are NOT required to open the simulator in a browser.
"""
import json
import struct
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

HERE = Path(__file__).resolve().parent


def stream(key, seq, counter, data):
    iv = struct.pack('<Q', counter) + struct.pack('>Q', seq % 2**32)
    ctx = Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor()
    return ctx.update(data) + ctx.finalize()


def seal(key, payload, seq):
    pad = 8 - ((1 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    # Fixed padding bytes let independent implementations produce identical wires.
    body = bytes([pad]) + payload + bytes((7 + j*19) % 256 for j in range(pad))
    wire = stream(key[32:], seq, 0, struct.pack('>I', len(body)))
    wire += stream(key[:32], seq, 1, body)
    return wire + Poly1305.generate_tag(stream(key[:32], seq, 0, bytes(32)), wire)


cases = []
for seq in (0, 3, 4, 257, 65536, 2**32 - 1):
    for length in (1, 7, 8, 31, 255, 1024):
        key = bytes((seq + i*11) % 256 for i in range(64))
        payload = bytes((j*17 + 3) % 256 for j in range(length))
        cases.append(dict(key=key.hex(), seq=seq, payload=payload.hex(),
                          wire=seal(key, payload, seq).hex()))

script = r'''
const fs=require('fs'),E=require('./engine.js');
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
const assert=(x,s)=>{if(!x)throw Error(s);};
for(const c of cases){
 const key=E.unhex(c.key),p=E.unhex(c.payload),wire=E.unhex(c.wire);
 const generated=E.seal(key,p,c.seq,n=>Uint8Array.from({length:n},(_,j)=>(7+j*19)%256));
 assert(E.hex(generated)===c.wire,'Python/JS wire mismatch');
 const opened=E.open(key,wire,c.seq);
 assert(opened.ok&&E.hex(opened.payload)===c.payload,'Python wire not decrypted correctly');
 assert(!E.open(key,wire,(c.seq+1)>>>0).ok,'Wrong sequence accepted');
 for(const offset of [0,5,wire.length-1]){const changed=wire.slice();changed[offset]^=1;assert(!E.open(key,changed,c.seq).ok,'Tampered packet accepted');}
}
const counts={};
for(const mode of ['legacy','reset','reject','strict']){
 let pass=0;
 for(let i=0;i<=8;i++)for(let d=0;d<=8;d++){
  const r=E.simulate({i,d,mode,seed:57611+i*9+d}).result;
  const expected=mode==='legacy'?i===d:mode==='reset'?d===0:mode==='reject'?i===0&&d===0:i===0&&d===0;
  assert(r.accepted===expected,`Wrong outcome: ${mode} ${i} ${d}`);
  assert(r.prefix_removed===(expected&&d>0),'Incorrect attack-success flag');
  if(r.accepted)pass++;
 }
 counts[mode]=pass;
}
for(const p of E.presets){
 const r=E.simulate(p).result;
 assert(r.accepted===['clean','matched','clean-strict'].includes(p.id),'Preset mismatch');
}
const matched=E.simulate({i:1,d:1});
const points=matched.trace.filter(t=>['KEXDH_REPLY: server contribution','Inject IGNORE 1 of 1','Server NEWKEYS','Client NEWKEYS','Delete EXT_INFO (packet #3)','SERVICE_REQUEST: ssh-userauth','SERVICE_ACCEPT: tag verified'].includes(t.title));
assert(JSON.stringify(points.map(t=>[t.cs,t.cr,t.ss,t.sr]))===JSON.stringify([[2,2,2,2],[2,3,2,2],[2,4,3,2],[3,4,3,3],[3,4,4,3],[4,4,4,4],[4,5,5,4]]),'Slide counter sequence mismatch');
assert(matched.result.received===11&&matched.result.ext_missing,'Matched result mismatch');
assert(E.simulate({i:1,d:1,mode:'strict'}).result.actual_dropped===0,'Deletion after handshake abort');
console.log(JSON.stringify({cross_implementation_packets:cases.length,grid_trials:324,grid_acceptance_counts:counts,control_scenarios:9,slide_counter_check:'passed',tampering_and_wrong_sequence_checks:'passed'},null,2));
'''
result = subprocess.run(['node', '-e', script], cwd=HERE,
                        input=json.dumps(cases), text=True, capture_output=True, check=True)
print(result.stdout)


## verification