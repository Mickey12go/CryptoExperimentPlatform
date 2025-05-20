import time
from Crypto.PublicKey import RSA,DSA,ECC
from Crypto.Signature import pkcs1_15,DSS
from Crypto.Hash import SHA256
from  gmssl import sm2,func
import  logging


logger=logging.getLogger(__name__)

#RSA算法实现
class RSAHandler:
    def generate_keys(self,key_size=2048):
       try:
           key=RSA.generate(key_size)
           private_key=key.export_key()
           public_key=key.public_key().export_key()
           return private_key,public_key
       except Exception as e:
           logger.error(f"RSA密钥生成失败：{str(e)}")
           raise

    def sign(self,private_key,message):
        try:
            key = RSA.import_key(private_key)
            h = SHA256.new(message.encode("utf-8"))
            signer = pkcs1_15.new(key)
            signature = signer.sign(h)
            timestamp = str(int(time.time()))
            return {"signature":signature.hex(),"timestamp":timestamp}
        except Exception as e:
            logger.error(f"RSA签名失败：{str(e)}")
            raise

    def verify(self,public_key,message,signed_message):
        try:#解析签名和时间戳
            signature_hex=signed_message.get("signature")
            timestamp=signed_message.get("timestamp")
            if not all([signature_hex,timestamp]):
                logger.warning("签名或时间戳缺失")
                return False
            signature = bytes.fromhex(signature_hex)
            key = RSA.import_key(public_key)
            h = SHA256.new(message.encode())
            verifier = pkcs1_15.new(key)
            verifier.verify(h,signature)
            #时间戳有效性检查
            current_time = int(time.time())
            stored_time = int(timestamp)
            if abs(current_time - stored_time) > 300:
                logger.warning("签名已过期")
                return False

            return True
        except(ValueError, TypeError,Exception) as e:
            logger.error(f"验证失败：{str(e)}")
            return False

#DSA算法实现
class DSAHandler:
    def generate_keys(self,key_size=2048):
        try:
            key = DSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.public_key().export_key()
            return private_key, public_key
        except Exception as e:
            logger.error(f"DSA密钥生成失败：{str(e)}")
            raise

    def sign(self,private_key,message):
        try:
            key = DSA.import_key(private_key)
            h = SHA256.new(message.encode("utf-8"))
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            timestamp = str(int(time.time()))
            return {"signature":signature.hex(),"timestamp":timestamp}
        except Exception as e:
            logger.error(f"DSA签名失败：{str(e)}")
            raise

    def verify(self,public_key,message,signed_message):
        try:
            signature_hex=signed_message.get("signature")
            timestamp=signed_message.get("timestamp")
            if not all([signature_hex,timestamp]):
                return False

            signature=bytes.fromhex(signature_hex)
            key = DSA.import_key(public_key)
            h = SHA256.new(message.encode("utf-8"))
            verifier = DSS.new(key, 'fips-186-3')
            verifier.verify(h, signature)
            #时间戳检查
            current_time = int(time.time())
            stored_time=int(timestamp)
            if abs(current_time - stored_time) > 300:
                return False
            return True

        except(ValueError, TypeError) as e:
            logger.error(f"DSA验证失败:{str(e)}")
            return False


#ECDSA算法实现
class ECDSAHandler:
    def generate_keys(self,curve="P-256"):
        try:
            key = ECC.generate(curve=curve)
            private_key = key.export_key(format='PEM')
            public_key = key.public_key().export_key(format='PEM')
            return private_key, public_key
        except Exception as e:
            logger.error(f"ECDSA密钥生成失败：{str(e)}")
            raise


    def sign(self,private_key,message):
        try:
            key = ECC.import_key(private_key)
            h = SHA256.new(message.encode("utf-8"))
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            timestamp = str(int(time.time()))
            return {
                "signature": signature.hex(),
                "timestamp": timestamp
            }
        except Exception as e:
            logger.error(f"ECDSA签名失败：{str(e)}")
            raise


    def verify(self,public_key,message,signed_message):
        try:
            signature_hex=signed_message.get("signature")
            timestamp=signed_message.get("timestamp")
            if not all([signature_hex,timestamp]):
                return False
            signature=bytes.fromhex(signature_hex)
            key = ECC.import_key(public_key)
            h = SHA256.new(message.encode())
            verifier = DSS.new(key, 'fips-186-3')
            verifier.verify(h, signature)

            current_time = int(time.time())
            stored_time=int(timestamp)
            if abs(current_time - stored_time) > 300:
                return False
            return True

        except (ValueError,TypeError)as e:
            logger.error((f"ECDSA验证失败：{str(e)}"))
            return False


#SM2算法实现
class SM2Handler:
    def generate_keys(self):
        try:
            #SM2的密钥对
            private_key=func.random_hex(32)#32字节私钥
            #创建临时实例用于生成公钥
            curve=sm2.default_ecc_table
            n=int(curve['N'],16)#曲线阶数
            Gx=int(curve['Gx'],16)#基点X坐标
            Gy=int(curve['Gy'],16)#基点Y坐标
            #将私钥转换成整数
            d=int(private_key,16)
            if not(1<=d<n):
                raise ValueError("私钥不在有效范围内")
            #计算公钥坐标
            sm2_crypt=sm2.CryptSM2(private_key=private_key,public_key="")
            public_key_x,public_key_y=sm2_crypt._kg(d,(Gx,Gy))
            #构造标准公钥格式(04||X||Y)
            public_key=f"04{public_key_x:064x}{public_key_y:064x}"

            #严格格式检查
            if not(
                public_key.startswith('04')
                and len(public_key)==130
                and all(c in '0123456789abcdef' for c in public_key[2:])
            ):
                raise ValueError("公钥格式不符合SM2标准")
            return private_key, public_key
        except Exception as e:
            logger.error(f"SM2密钥生成失败：{str(e)}")
            raise



    def sign(self,private_key,message):
        try:
            sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")
            data = message.encode()
            random_hex_str = func.random_hex(sm2_crypt.para_len)
            signature = sm2_crypt.sign(data, random_hex_str)
            timestamp = str(int(time.time()))
            return {
                "signature": signature.hex(),
                "timestamp": timestamp
            }
        except Exception as e:
            logger.error(f"SM2签名失败：{str(e)}")
            raise


    def verify(self,public_key,message,signed_message):
        try:
            signature_hex = signed_message.get("signature")
            timestamp=signed_message.get("timestamp")
            if not all([signature_hex,timestamp]):
                return False

            signature=bytes.fromhex(signature_hex)
            sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)
            data = message.encode("utf-8")
            verify_result = sm2_crypt.verify(signature, data)

            current_time = int(time.time())
            if abs(current_time - int(timestamp)) > 300 or not verify_result:
                return False
            return True
        except(ValueError,Exception)as e:
            logger.error(f"SM2验证失败：{str(e)}")
            return False



