from inspect import signature
from Crypto.PublicKey import RSA,DSA,ECC
from Crypto.Signature import pkcs1_15,DSS
from Crypto.Hash import SHA256
from  gmssl import sm2,func

#RSA算法实现
class RSAHandler:
    def generate_keys(self):
        key=RSA.generate(2048)
        private_key=key.export_key()
        public_key=key.public_key().export_key()
        return private_key,public_key

    def sign(self,private_key,message):
        key=RSA.import_key(private_key)
        h=SHA256.new(message.encode())
        signer=pkcs1_15.new(key)
        signature=signer.sign(h)
        return signature

    def verify(self,public_key,message,signature):
        key=RSA.import_key(public_key)
        h=SHA256.new(message.encode())
        verifier=pkcs1_15.new(key)
        try:
            verifier.verify(h,signature)
            return True
        except(ValueError,TypeError):
            return False

#DSA算法实现
class DSAHandler:
    def generate_keys(self):
        key=DSA.generate(2048)
        private_key=key.export_key()
        public_key=key.public_key().export_key()
        return private_key,public_key

    def sign(self,private_key,message):
        key = DSA.import_key(private_key)
        h = SHA256.new(message.encode())
        signer = DSS.new(key,'fips-186-3')
        signature = signer.sign(h)
        return signature

    def verify(self,public_key,message,signature):
        key=DSA.import_key(public_key)
        h=SHA256.new(message.encode())
        verifier=DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h,signature)
            return True
        except ValueError:
            return False


#ECDSA算法实现
class ECDSAHandler:
    def generate_keys(self):
        key=ECC.generate(curve='P-256')
        private_key=key.export_key(format='PEM')
        public_key=key.public_key().export_key(format='PEM')
        return private_key,public_key

    def sign(self,private_key,message):
        key = ECC.import_key(private_key)
        h = SHA256.new(message.encode())
        signer = DSS.new(key,'fips-186-3')
        signature = signer.sign(h)
        return signature

    def verify(self,public_key,message,signature):
        key=ECC.import_key(public_key)
        h=SHA256.new(message.encode())
        verifier=DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h,signature)
            return True
        except ValueError:
            return False

#SM2算法实现
class SM2Handler:
    def generate_keys(self):
       private_key=func.random_hex(32)
       public_key=sm2.CryptSM2(private_key=private_key).get_pubkey()
       return private_key,public_key

    def sign(self,private_key,message):
        sm2_crypt=sm2.CryptSM2(private_key=private_key,public_key='')
        data=message.encode()
        random_hex_str=func.random_hex(sm2_crypt.para_len)
        signature=sm2_crypt.sign(data,random_hex_str)
        return signature
    def verify(self,public_key,message,signature):
        sm2_crypt=sm2.CryptSM2(private_key='',public_key=public_key)
        data=message.encode()
        return sm2_crypt.verify(signature,data)