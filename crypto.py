from Crypto.Util.asn1 import DerSequence, DerObjectId, DerOctetString, DerNull
import hashlib
from math import gcd

class VerifyingKey:
    def __init__(self, n, e, bits=2048):
        self.n = n
        self.e = e

        self.bits = bits

    # https://datatracker.ietf.org/doc/html/rfc2313#section-10.2
    # Note: The only hash algorithm we accept is SHA256.
    def verify(self, m, s):
        if len(s) != self.bits//8:
            raise Exception('incorrect signature length')
        s = int.from_bytes(s, 'big')

        k = pow(s, self.e, self.n)
        k = int.to_bytes(k, self.bits//8, 'big')
        if k[0] != 0x00:
            raise Exception('incorrect prefix')
        if k[1] != 0x01:
            raise Exception('incorrect prefix')
        
        padding, digest_info = k[2:].split(b'\x00', 1)

        if len(padding) < 8:
            raise Exception('invalid padding length')
        if padding != b'\xff'*len(padding):
            raise Exception('invalid padding content')

        sequence = DerSequence()
        sequence.decode(digest_info)
        _digest_algorithm_identifier, _digest = sequence

        sequence = DerSequence()
        sequence.decode(_digest_algorithm_identifier)
        _digest_algorithm_identifier = sequence[0]

        object_id = DerObjectId()
        object_id.decode(_digest_algorithm_identifier)
        digest_algorithm_identifier = object_id.value
        if digest_algorithm_identifier != '2.16.840.1.101.3.4.2.1':
            raise Exception('invalid digest algorithm identifier')

        _null = sequence[1]
        null = DerNull()
        null.decode(_null)

        octet_string = DerOctetString()
        octet_string.decode(_digest)
        digest = octet_string.payload

        if hashlib.sha256(m).digest() != digest:
            raise Exception('mismatch digest')
        return True


class SigningKey:
    def __init__(self, p, q, e, bits=2048):
        if gcd(p-1, e) != 1: raise Exception('p-1 and e are not coprime')
        if gcd(q-1, e) != 1: raise Exception('q-1 and e are not coprime')
        phi_n = (p-1) * (q-1)

        self.p = p
        self.q = q
        self.e = e
        self.n = p * q
        self.d = pow(e, -1, phi_n)

        self.bits = bits

    def verifying_key(self):
        return VerifyingKey(self.p*self.q, self.e, self.bits)

    # https://datatracker.ietf.org/doc/html/rfc2313#section-10.1
    def sign(self, m):
        digest_algorithm_identifier = DerSequence([
            DerObjectId('2.16.840.1.101.3.4.2.1').encode(),
            DerNull().encode()
        ])
        digest = hashlib.sha256(m).digest()

        digest_info = DerSequence(([
            digest_algorithm_identifier,
            DerOctetString(digest).encode()
        ]))

        encryption_block  = bytes.fromhex('00') 
        encryption_block += bytes.fromhex('01') # block type for signature
        encryption_block += b'\xff'*(self.bits//8 - 3 - len(digest_info.encode()))
        encryption_block += bytes.fromhex('00')
        encryption_block += digest_info.encode()

        encryption_block = int.from_bytes(encryption_block, 'big')
        s = pow(encryption_block, self.d, self.n)
        s = int.to_bytes(s, self.bits//8, 'big')

        return s
