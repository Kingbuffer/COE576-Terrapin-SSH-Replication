"""Offline SSH packet/sequence-state experiment, independently assembled for COE576.
No sockets, SSH credentials, network interception, or authors' exploit code.
Cipher construction: Miller & Josefsson draft, sections 3-4. Not a full SSH stack.
"""
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidSignature

MOD = 2**32

def stream(key, seq, counter, data):
    # cryptography exposes original ChaCha20: LE 64-bit block counter + 64-bit nonce.
    # SSH encodes the sequence number into the nonce in network (big-endian) order.
    iv = struct.pack('<Q', counter) + struct.pack('>Q', seq % MOD)
    ctx = Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor()
    return ctx.update(data) + ctx.finalize()

def ssh_string(value):
    return struct.pack('>I', len(value)) + value

def messages(count):
    # RFC8308 EXT_INFO with one extension, then SERVICE_ACCEPT (RFC4253).
    ext = b'\x07' + struct.pack('>I', 1) + ssh_string(b'ping@openssh.com') + ssh_string(b'0')
    accept = b'\x06' + ssh_string(b'ssh-userauth')
    return [ext, accept] + [b'\x02' + ssh_string(b'offline filler') for _ in range(count-2)]

class PacketCipher:
    def __init__(self, key):
        if len(key) != 64:
            raise ValueError('64 bytes of key material required')
        self.main, self.header = key[:32], key[32:]

    def seal(self, payload, seq, rng):
        # OpenSSH AEAD padding: encrypted body excluding 4-byte length is aligned to 8.
        pad = 8 - ((1 + len(payload)) % 8)
        if pad < 4:
            pad += 8
        body = bytes([pad]) + payload + rng.randbytes(pad)
        length = struct.pack('>I', len(body))
        wire = stream(self.header, seq, 0, length) + stream(self.main, seq, 1, body)
        polykey = stream(self.main, seq, 0, bytes(32))
        return wire + Poly1305.generate_tag(polykey, wire)

    def open(self, wire, seq):
        if len(wire) < 24:
            raise ValueError('short packet')
        ciphertext, tag = wire[:-16], wire[-16:]
        polykey = stream(self.main, seq, 0, bytes(32))
        # Complete packet boundaries are supplied by the experiment; verify before parsing.
        Poly1305.verify_tag(polykey, ciphertext, tag)
        length = struct.unpack('>I', stream(self.header, seq, 0, ciphertext[:4]))[0]
        if length != len(ciphertext)-4 or length % 8:
            raise ValueError('bad framing')
        body = stream(self.main, seq, 1, ciphertext[4:])
        pad = body[0]
        if not 4 <= pad <= 255 or pad + 1 >= len(body):
            raise ValueError('bad padding')
        return body[1:-pad]

@dataclass
class Receiver:
    cipher: PacketCipher
    seq: int
    reject_optional: bool = False
    reset: bool = False
    phase: str = 'handshake'

    def inject_ignore(self):
        if self.phase != 'handshake':
            raise ValueError('wrong phase')
        if self.reject_optional:
            self.phase = 'aborted'
            raise ValueError('strict handshake rejected optional message')
        self.seq = (self.seq + 1) % MOD

    def newkeys(self):
        self.seq = 0 if self.reset else (self.seq + 1) % MOD
        self.phase = 'encrypted'

    def receive(self, wire):
        if self.phase != 'encrypted':
            raise ValueError('channel not active')
        try:
            payload = self.cipher.open(wire, self.seq)
        except (InvalidSignature, ValueError):
            self.phase = 'aborted'
            raise
        self.seq = (self.seq + 1) % MOD
        return payload


def experiment(rng, injected=1, dropped=1, reset=False, reject_optional=False,
               tamper=False, base=None, packet_count=12):
    """Return measured outcomes; success is based on actual decryption, not i==d.

    base is the common directional counter immediately BEFORE NEWKEYS. Legitimate
    KEX messages and host-key authentication are abstracted. An attacker receives
    only already-framed ciphertext packets in this harness, never the session key.
    Reset assumes BOTH peers have negotiated the safeguard.
    """
    if not 0 <= dropped < packet_count or injected < 0:
        raise ValueError('invalid experiment dimensions')
    if base is None:
        base = rng.randrange(2, 1000)
    cipher = PacketCipher(rng.randbytes(64))
    receiver = Receiver(cipher, base, reject_optional, reset)
    for _ in range(injected):
        try:
            receiver.inject_ignore()
        except ValueError:
            return dict(accepted=False, prefix_removed=False, ext_missing=False,
                        status='handshake_rejected', received=0)
    receiver.newkeys()
    sender_seq = 0 if reset else (base+1) % MOD
    payloads = messages(packet_count)
    packets = [cipher.seal(p, (sender_seq+j) % MOD, rng) for j,p in enumerate(payloads)]
    # The simulated attacker only drops opaque packets or flips a ciphertext bit.
    forwarded = packets[dropped:]
    if tamper:
        w = bytearray(forwarded[0]); w[5] ^= 1; forwarded[0] = bytes(w)
    recovered = []
    try:
        for wire in forwarded:
            recovered.append(receiver.receive(wire))
    except (InvalidSignature, ValueError):
        return dict(accepted=False, prefix_removed=False, ext_missing=False,
                    status='packet_rejected', received=len(recovered))
    intact = recovered == payloads[dropped:]
    ext_missing = intact and all(p[0] != 7 for p in recovered)
    return dict(accepted=intact, prefix_removed=intact and dropped>0,
                ext_missing=ext_missing, status='accepted', received=len(recovered))
