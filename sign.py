'''
variables:
dca:    Master secret key of certificate authority (CA)
rid:    User defined random
rca:    CA defined random
Gca:    CA's public key
IDu:    User's identifier -- MAC in hexstring
Rid:    User's identifier ecc corresponding point
Rca:    CA's random ecc corresponding point
Certid: User's certificate
r_cert:      Generated value r_cert
did:    User's private key
Pid:    User's public key
'''

from Cryptodome.Util import number
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from fastecdsa import keys, curve, point
from utils import pointToHexStr
import uuid
import os

from dataset import SigncryptionDataset


class Signcryption(object):
    '''
        Combination class to facilitate the use of several objects

        server: signcryption.Server The server which manages the certificates
        sender: signcryption.User   The sender of messages
        receiver:   signcryption.User   The receiver of messages
    '''
    server = None
    sender = None
    receiver = None

    def __init__(self):
        # setup the signcryption system
        self.server = Server(0x9919f1811b11c291831d5b4f143093ed24bf91889195e666ee367cff2832052a,
                             0xad7e3967d5dd5daa0be60bb3ba5146dc7bd43626e31ff01df8dc9acf8eb47763)
        self.sender = User(
            0, self.server, 0xdf9fd986bd85acc9e401ecafeb74248c8bacfd986fccd53f7e6ef6ccc1170fe0)
        self.receiver = User(
            1, self.server, 0xfb19afa9a02f86a78769b09aa8cd5b603a5d4dbc735608205cd1d49c63c88544)
        self.sender.genCert()
        self.receiver.genCert()


class Server(object):
    '''
        dca:    Master secret key of certificate authority (CA)
        rca:    CA defined random
        Gca:    CA's public key
        Rca:    CA's random ecc corresponding point
    '''
    dca = None
    rca = None
    Gca = None
    Rca = None

    def __init__(self, dca=None, rca=None):
        if (dca and rca) is None:
            self.dca = number.getRandomNBitInteger(256)
            self.rca = number.getRandomNBitInteger(256)
        elif (dca or rca) is not None:
            self.dca = dca
            self.rca = rca
        else:
            print ("Incorrect usage")
            return
        # 1 Setup
        self.Gca = self.dca * curve.secp256k1.G
        # TODO: Is this always new random value in request cert?
        self.Rca = self.rca * curve.secp256k1.G

    def reqCert(self, (IDu, Rid)):
        assert isinstance(IDu, str) and isinstance(Rid, point.Point)
        # 3 Certification - CA
        Certid = self.Rca + Rid
        sha = SHA256.new()
        sha.update(pointToHexStr(Certid) + IDu)
        r_cert = long(sha.hexdigest(), 16) * self.rca + self.dca
        return (Certid, r_cert)

    def getPublicParam(self):
        return self.Gca

    def __str__(self):
        return "Singcryption server {{ dca: {}\
        rca: {} \
        Gca: {} \
        Rca: {} }}".format(hex(self.dca), hex(self.rca), self.Gca, self.Rca)


class User(object):
    '''
        rid:    User defined random
        IDu:    User's identifier -- MAC in hexstring
        Rid:    User's identifier ecc corresponding point
        Certid: User's certificate
        r_cert:      Generated value r_cert
        did:    User's private key
        Pid:    User's public key
    '''
    rid = None
    IDu = None
    Rid = None
    Certid = None
    r_cert = None
    did = None
    Pid = None
    # Certificate authority
    ca = None

    def __init__(self, idmodifier, server, rid=None):
        if rid is None:
            self.rid = number.getRandomNBitInteger(256)
        elif isinstance(rid, long):
            self.rid = rid
        else:
            print ("Incorrect usage")
            return
        # Initialize
        assert isinstance(server, Server)
        self.ca = server
        # 2 Initialize keypair
        self.IDu = '{:0{}x}'.format(uuid.getnode(
        ) + idmodifier, uuid.getnode().bit_length()/4).decode("hex")  # MAC in hexstring
        self.Rid = self.rid * curve.secp256k1.G

    def getPublicParam(self):
        '''
            Returns (IDu, Certid)
        '''
        return (self.IDu, self.Certid)

    def genCert(self):
        '''
            Process certification
        '''
        # 3 Certification - request cert from CA
        (self.Certid, self.r_cert) = self.ca.reqCert((self.IDu, self.Rid))
        # 3 Certification - User
        assert isinstance(self.Certid, point.Point) and isinstance(
            self.r_cert, long)
        sha = SHA256.new()
        sha.update(pointToHexStr(self.Certid) + self.IDu)
        self.did = (long(sha.hexdigest(), 16) * self.rid +
                    self.r_cert) % curve.secp256k1.q
        self.Pid = self.did * curve.secp256k1.G
        # validation
        assert self.validatePCERT()
        return (self.IDu, self.Certid)

    def validatePCERT(self):
        '''
            Check if Pid = H(Certid || IDu)Certid + Gca
        '''
        # Retrieve values
        Gca = self.ca.getPublicParam()
        # Check if Pid = H(Certid || IDu)Certid + Gca
        sha = SHA256.new()
        sha.update(pointToHexStr(self.Certid) + self.IDu)
        return self.Pid == long(sha.hexdigest(), 16) * self.Certid + Gca

    def signcrypt(self, message, receiver, precomp=None, nonce=None):
        '''
            Signcryption process
            message:    Message to be encrypted and signed
            receiver:   User object - Destination of message
            @return:    SignCrypt object - Encrypted and signed message
        '''
        assert isinstance(receiver, User)
        assert message is not None
        # Get parameters
        (IDr, Certr) = receiver.getPublicParam()
        Gca = self.ca.getPublicParam()
        # variable init
        (Pr, r, R, k, key) = (None, None, None, None, None)
        if precomp is None:
            print (" precomp is empty")
            # Compute receiver's key
            Pr = computePubKey((IDr, Certr), Gca)
            # Random value
            r = number.getRandomNBitInteger(256)
            R = r * curve.secp256k1.G
            # Key derivation
            k = r * Pr
            print ("k: {}").format(str(k))
            sha = SHA256.new()
            sha.update(pointToHexStr(k))
            key = long(sha.hexdigest(), 16)
        else:
            print (" precomp is full")
            if isinstance(precomp, PreComp):
                (Pr, r, R, k, key) = precomp.getValues()
            elif isinstance(precomp, SigncryptionDataset):
                (Pr, r, R, k, key) = precomp.get_values()
            else:
                raise TypeError(
                    "Expected precomp of type PreComp or SigncryptionDataset")
        # Ciphertext
        ccm = AESCCM('{:064x}'.format(key).decode("hex"))
        if nonce is None:
            nonce = os.urandom(13)
        ctext = ccm.encrypt(nonce, message, None)
        # hash computed
        sha = SHA256.new()
        e_input = message + \
            pointToHexStr(R) + self.IDu + pointToHexStr(self.Pid) + \
            pointToHexStr(self.Certid)
        print("e_input: {:x}".format(long(e_input.encode("hex"), 16)))
        sha.update(e_input)
        h = long(sha.hexdigest(), 16)
        # Signature
        D = (r - h * self.did) % curve.secp256k1.q
        signcrypt = SignCrypt(h, (ctext, nonce), D)
        return signcrypt

    def unsigncrypt(self, signcrypt, sender):
        '''
            Process of decryption and signature verification
            signcrypt:  Encrypted and signed message
            sender:     User object - origin of signcrypt
            @return:    Decrypted message if valid else assertion error
        '''
        assert isinstance(sender, User)
        assert isinstance(signcrypt, SignCrypt)
        (h, (ctext, nonce), D) = signcrypt.getValues()
        # Get parameters
        (IDs, Certs) = sender.getPublicParam()
        Gca = self.ca.getPublicParam()
        # Compute pubkey
        Ps = computePubKey((IDs, Certs), Gca)
        # compute Rstar
        Rstar = D * curve.secp256k1.G + h * Ps
        # derive key
        kstar = self.did * Rstar
        print ("kstar: {}").format(str(kstar))
        sha = SHA256.new()
        sha.update(pointToHexStr(kstar))
        keystar = long(sha.hexdigest(), 16)
        # message decryption
        ccm = AESCCM('{:064x}'.format(keystar).decode("hex"))
        mstar = ccm.decrypt(nonce, ctext, None)
        print ("Decrypted value: {}").format(mstar)
        # check validity
        sha = SHA256.new()
        sha.update(mstar + pointToHexStr(Rstar) + IDs +
                   pointToHexStr(Ps) + pointToHexStr(Certs))
        hstar = long(sha.hexdigest(), 16)
        assert h == hstar
        return mstar

    def __str__(self):
        return "Signcryption user {{ rid: {} \
        IDu: {} \
        Rid: {} \
        Certid: {} \
        r_cert: {} \
        did: {} \
        Pid: {} \
        ca: {} }}".format(hex(self.rid), self.IDu, self.Rid, self.Certid, hex(self.r_cert), hex(self.did), self.Pid, self.ca)


class SignCrypt(object):
    '''
        Cipher and signature object created by the signcryption
        h:  Verification hash
        C:  (Cipher text, ?Nonce)
        D:  Signature
    '''
    h = None
    C = (None, None)
    D = None

    def __init__(self, h, C, D):
        self.h = h
        self.C = C
        self.D = D

    def getValues(self):
        return (self.h, self.C, self.D)

    def __str__(self):
        return "SignCrypt: h: {}, C: {}, D: {}".format(hex(self.h), self.C, hex(self.D))


class PreComp(object):
    '''
        Pr: Public key of the receiver
        r:  ECC point - Random value
        R:  ECC point - of r
        k:  ECC point - Encryption key
        key: long - Encryption key
    '''
    Pr = None
    r = None
    R = None
    k = None
    key = None

    def __init__(self, Pr, r, R, k, key=None):
        '''
            Pr: Public key of the receiver
            r:  ECC point - Random value
            R:  ECC point - of r
            k:  ECC point - Encryption key
            key: long - Encryption key
        '''
        assert isinstance(Pr, point.Point)
        self.Pr = Pr
        assert isinstance(r, long)
        self.r = r
        assert isinstance(R, point.Point)
        self.R = R
        assert isinstance(k, point.Point)
        self.k = k
        if key is None:
            sha = SHA256.new()
            sha.update(pointToHexStr(k))
            key = long(sha.hexdigest(), 16)
        self.key = key

    def getValues(self):
        '''
            Returns: (Pr, r, R, k, key)
        '''
        return (self.Pr, self.r, self.R, self.k, self.key)

    def __str__(self):
        return 'PreComp: Pr: {}, r: {}, R: {}, k: {}, key: {}'.format(self.Pr, hex(self.r), self.R, self.k, hex(self.key))

    @staticmethod
    def genObject(Pr, r=None):
        '''
            Generate values using Pr and (opt) r
            Pr: ECC point - Public key of receiver
            r: long (optional) - random value, if None 256 bit random generated
        '''
        if r is None:
            r = number.getRandomNBitInteger(256)
        return PreComp(Pr, r, r * curve.secp256k1.G, r * Pr)

    @staticmethod
    def genObjects(Pr, amount):
        '''
            Generate amount of PreComp objects
            Pr: ECC point - Public key of receiver
            amount: Amount of PreComp objects to generate
            @return: List of generated PreComp objects
        '''
        objects = []
        for i in range(amount):
            objects.append(PreComp.genObject(Pr))
        return objects


def computePubKey((ID, Cert), Gca):
    '''
        Compute public key:
            P = H(Cert || ID)Cert + Gca
    '''
    # Compute pubkey
    sha = SHA256.new()
    sha.update(pointToHexStr(Cert) + ID)
    P = long(sha.hexdigest(), 16) * Cert + Gca
    return P


if __name__ == "__main__":
    import time
    message = "Hello World!"
    # Initialization
    # 1
    server = Server()
    # 2
    sender = User(0, server)
    receiver = User(1, server)
    # 3
    sender.genCert()
    receiver.genCert()
    # -- Tests   --
    print ("Signcryption test 1: regular")
    print ("Original message: {}").format(message)
    # 4
    time_start = time.time()
    csr = sender.signcrypt(message, receiver)
    time_end = time.time()
    mstar = receiver.unsigncrypt(csr, sender)
    # 5
    print ("CSR: {}").format(csr)
    print ("Decrypted and verified message: {}").format(mstar)
    print ("Timings: signcryption(regular): {} ms").format((time_end - time_start) * 1000)
    # -- Precomputation test --
    print ("Signcryption test 2: precomputation")
    print ("Original message: {}").format(message)
    # 4
    precomp = PreComp.genObject(receiver.Pid)
    time_start = time.time()
    csr = sender.signcrypt(message, receiver, precomp)
    time_end = time.time()
    mstar = receiver.unsigncrypt(csr, sender)
    # 5
    print ("CSR: {}").format(csr)
    print ("Decrypted and verified message: {}").format(mstar)
    print ("Timings: signcryption(precomp): {} ms").format((time_end - time_start) * 1000)
