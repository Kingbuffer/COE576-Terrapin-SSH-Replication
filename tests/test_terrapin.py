import random
import unittest
from src.terrapin import PacketCipher, Receiver, experiment, stream
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidSignature

class PacketTests(unittest.TestCase):
    def test_chacha_known_vector(self):
        # Published all-zero original ChaCha20 test vector, first 64 bytes.
        expected = ('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'
                    'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586')
        self.assertEqual(stream(bytes(32),0,0,bytes(64)).hex(), expected)
    def test_poly1305_rfc8439_vector(self):
        key = bytes.fromhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
        self.assertEqual(Poly1305.generate_tag(key,b'Cryptographic Forum Research Group').hex(),
                         'a8061dc1305136c6c22b8baf0c0127a9')
    def test_packet_lengths_and_wrong_nonce(self):
        rng=random.Random(1); c=PacketCipher(rng.randbytes(64))
        for n in [1,2,7,8,9,31,255,1024]:
            p=rng.randbytes(n); w=c.seal(p,123,rng)
            self.assertEqual(c.open(w,123),p)
            with self.assertRaises(InvalidSignature): c.open(w,124)
    def test_controls_and_matched_prefix(self):
        for i in range(5):
            for d in range(5):
                r=experiment(random.Random(100+i*5+d),i,d)
                self.assertEqual(r['accepted'],i==d)
                self.assertEqual(r['prefix_removed'],i==d and d>0)
    def test_safeguards_preserve_clean_channel(self):
        for reset,reject in [(True,False),(False,True),(True,True)]:
            self.assertTrue(experiment(random.Random(5),0,0,reset,reject)['accepted'])
            self.assertFalse(experiment(random.Random(5),1,1,reset,reject)['prefix_removed'])
    def test_ciphertext_tampering_fails(self):
        self.assertFalse(experiment(random.Random(1),1,1,tamper=True)['accepted'])
    def test_extension_loss_and_remaining_packets(self):
        r=experiment(random.Random(2),1,1)
        self.assertTrue(r['ext_missing']); self.assertEqual(r['received'],11)
    def test_aborted_receiver_cannot_resume(self):
        rng=random.Random(1); c=PacketCipher(rng.randbytes(64)); r=Receiver(c,3)
        r.newkeys()
        with self.assertRaises(InvalidSignature): r.receive(c.seal(b'a',5,rng))
        with self.assertRaises(ValueError): r.receive(c.seal(b'a',4,rng))

if __name__=='__main__': unittest.main()
