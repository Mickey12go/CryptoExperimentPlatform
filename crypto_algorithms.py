import time
import os
import json
import hmac
import hashlib
import numpy as np
from typing import List, Dict, Any
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

import logging

logger = logging.getLogger(__name__)

try:
    # 尝试导入 Open Quantum Safe 的 Python 绑定
    # 现在已确认，安装的 liboqs-python 包提供了名为 'oqs' 的模块
    import oqs
    OQS_AVAILABLE = True
    logger.info("oqs (liboqs-python) 模块已成功导入.")
except ImportError:
    oqs = None  # 如果导入失败，将 oqs 设为 None
    OQS_AVAILABLE = False
    logger.warning("未安装 oqs (liboqs-python) 模块，后量子算法功能将不可用.")

# ------------------------- SM2 实现（使用 SECP256K1 曲线） -------------------------
class SM2Handler:
    def generate_keys(self, curve="SECP256K1"):
        """生成 SM2 兼容密钥对（支持多种椭圆曲线）"""
        try:
            # 支持多种曲线
            curve_map = {
                "SECP256K1": ec.SECP256K1(),
                "SECP256R1": ec.SECP256R1(),
                "SECP384R1": ec.SECP384R1()
            }
            if curve not in curve_map:
                raise ValueError(f"Unsupported curve: {curve}")
            private_key = ec.generate_private_key(curve_map[curve], default_backend())
            private_value = private_key.private_numbers().private_value
            # 动态计算字节长度，兼容不同曲线
            key_size_bytes = (private_value.bit_length() + 7) // 8
            private_hex = private_value.to_bytes(key_size_bytes, 'big').hex()
            public_key_obj = private_key.public_key()
            public_bytes = public_key_obj.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            public_hex = public_bytes.hex()
            if not private_hex or not public_hex:
                raise ValueError("生成的密钥为空")
            return private_hex, public_hex
        except Exception as e:
            logger.error(f"SM2密钥生成失败：{str(e)}", exc_info=True)
            raise

    # 其他方法保持不变...

    def sign(self, private_key, message, curve="SECP256K1"):
        """生成 SM2 签名（修复哈希计算流程，支持多曲线）"""
        try:
            if not private_key or not message:
                raise ValueError("私钥或消息不能为空")
            curve_map = {
                "SECP256K1": ec.SECP256K1(),
                "SECP256R1": ec.SECP256R1(),
                "SECP384R1": ec.SECP384R1()
            }
            if curve not in curve_map:
                raise ValueError(f"Unsupported curve: {curve}")
            private_value = int(private_key, 16)
            private_key_obj = ec.derive_private_key(
                private_value, curve_map[curve], default_backend()
            )
            data = message.encode('utf-8')
            hash_obj = hashes.Hash(hashes.SHA256(), default_backend())
            hash_obj.update(data)
            digest = hash_obj.finalize()
            signature = private_key_obj.sign(
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            r, s = utils.decode_dss_signature(signature)
            return {
                "algorithm": "SM2",
                "message": message,
                "signature": f"{r:064x}{s:064x}",
                "timestamp": str(int(time.time()))
            }
        except Exception as e:
            logger.error(f"SM2签名失败：{str(e)}", exc_info=True)
            raise

    def verify(self, public_key, message, signature_dict, curve="SECP256K1"):
        """验证 SM2 签名（修复哈希计算流程，支持多曲线）"""
        try:
            if not public_key or not message or not signature_dict:
                return False
            curve_map = {
                "SECP256K1": ec.SECP256K1(),
                "SECP256R1": ec.SECP256R1(),
                "SECP384R1": ec.SECP384R1()
            }
            if curve not in curve_map:
                raise ValueError(f"Unsupported curve: {curve}")
            public_bytes = bytes.fromhex(public_key)
            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                curve_map[curve], public_bytes
            )
            signature_hex = signature_dict.get("signature", "")
            if len(signature_hex) != 128:
                raise ValueError("无效的SM2签名长度")
            r = int(signature_hex[:64], 16)
            s = int(signature_hex[64:], 16)
            signature = utils.encode_dss_signature(r, s)
            data = message.encode('utf-8')
            hash_obj = hashes.Hash(hashes.SHA256(), default_backend())
            hash_obj.update(data)
            digest = hash_obj.finalize()
            public_key_obj.verify(
                signature,
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            return True
        except Exception as e:
            logger.error(f"SM2验证失败：{str(e)}", exc_info=True)
            return False


# ------------------------- 其他算法实现 -------------------------
class RSAHandler:
    """RSA 算法实现"""

    def generate_keys(self, key_size=2048):
        try:
            key = RSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            return private_key.decode(), public_key.decode()
        except Exception as e:
            logger.error(f"RSA密钥生成失败：{str(e)}", exc_info=True)
            raise

    def sign(self, private_key, message):
        try:
            key = RSA.import_key(private_key.encode())
            h = SHA256.new(message.encode('utf-8'))
            signer = pkcs1_15.new(key)
            signature = signer.sign(h)
            return {
                "algorithm": "RSA",
                "message": message,
                "signature": signature.hex()
            }
        except Exception as e:
            logger.error(f"RSA签名失败：{str(e)}", exc_info=True)
            raise

    def verify(self, public_key, message, signature_dict):
        try:
            key = RSA.import_key(public_key.encode())
            h = SHA256.new(message.encode('utf-8'))
            verifier = pkcs1_15.new(key)
            signature = bytes.fromhex(signature_dict["signature"])
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            logger.warning(f"RSA验证失败：{str(e)}")
            return False
        except Exception as e:
            logger.error(f"RSA验证出错：{str(e)}", exc_info=True)
            return False


class DSAHandler:
    """DSA 算法实现"""

    def generate_keys(self, key_size=2048):
        try:
            key = DSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            return private_key.decode(), public_key.decode()
        except Exception as e:
            logger.error(f"DSA密钥生成失败：{str(e)}", exc_info=True)
            raise

    def sign(self, private_key, message):
        try:
            key = DSA.import_key(private_key.encode())
            h = SHA256.new(message.encode('utf-8'))
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            return {
                "algorithm": "DSA",
                "message": message,
                "signature": signature.hex()
            }
        except Exception as e:
            logger.error(f"DSA签名失败：{str(e)}", exc_info=True)
            raise

    def verify(self, public_key, message, signature_dict):
        try:
            key = DSA.import_key(public_key.encode())
            h = SHA256.new(message.encode('utf-8'))
            verifier = DSS.new(key, 'fips-186-3')
            signature = bytes.fromhex(signature_dict["signature"])
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            logger.warning(f"DSA验证失败：{str(e)}")
            return False
        except Exception as e:
            logger.error(f"DSA验证出错：{str(e)}", exc_info=True)
            return False


class ECDSAHandler:
    """ECDSA 算法实现"""

    def generate_keys(self, curve="P-256"):
        try:
            key = ECC.generate(curve=curve)
            private_key = key.export_key(format='PEM')
            public_key = key.public_key().export_key(format='PEM')
            return private_key, public_key
        except Exception as e:
            logger.error(f"ECDSA密钥生成失败：{str(e)}", exc_info=True)
            raise

    def sign(self, private_key, message):
        try:
            key = ECC.import_key(private_key)
            h = SHA256.new(message.encode('utf-8'))
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            return {
                "algorithm": "ECDSA",
                "message": message,
                "signature": signature.hex()
            }
        except Exception as e:
            logger.error(f"ECDSA签名失败：{str(e)}", exc_info=True)
            raise

    def verify(self, public_key, message, signature_dict):
        try:
            key = ECC.import_key(public_key)
            h = SHA256.new(message.encode('utf-8'))
            verifier = DSS.new(key, 'fips-186-3')
            signature = bytes.fromhex(signature_dict["signature"])
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            logger.warning(f"ECDSA验证失败：{str(e)}")
            return False
        except Exception as e:
            logger.error(f"ECDSA验证出错：{str(e)}", exc_info=True)
            return False


import time
import json
import numpy as np
from typing import List, Dict, Any


class PerformanceTester:
    """数字签名算法性能测试器"""

    def __init__(self):
        self.handlers = {
            "RSA": RSAHandler(),
            "DSA": DSAHandler(),
            "ECDSA": ECDSAHandler(),
            "SM2": SM2Handler()
        }
        self.results = []

    def run_test(
            self,
            algorithm: str,
            key_size: int = 2048,
            curve: str = "P-256",
            message_sizes: List[int] = [128, 1024, 8192],
            iterations: int = 50
    ) -> None:
        """运行指定算法的性能测试

        Args:
            algorithm: 算法名称，可选值：RSA, DSA, ECDSA, SM2
            key_size: 密钥长度（仅适用于RSA/DSA）
            curve: 曲线类型（仅适用于ECDSA/SM2）
            message_sizes: 测试消息大小列表（字节）
            iterations: 每个测试用例的迭代次数
        """
        if algorithm not in self.handlers:
            raise ValueError(f"不支持的算法: {algorithm}")

        handler = self.handlers[algorithm]

        # 为每种消息大小运行测试
        for msg_size in message_sizes:
            message = "A" * msg_size

            # 1. 密钥生成测试
            key_gen_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                if algorithm in ["RSA", "DSA"]:
                    private_key, public_key = handler.generate_keys(key_size)
                else:  # ECDSA, SM2
                    private_key, public_key = handler.generate_keys(curve)
                key_gen_times.append(time.perf_counter() - start_time)

            # 2. 签名生成测试
            sign_times = []
            sig_lengths = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                if algorithm == "SM2":
                    signature_dict = handler.sign(private_key, message, curve)
                else:
                    signature_dict = handler.sign(private_key, message)
                sign_times.append(time.perf_counter() - start_time)

                # 计算签名长度
                if algorithm == "SM2":
                    sig_length = len(signature_dict["signature"]) // 2  # 十六进制字符串转字节
                else:
                    sig_length = len(bytes.fromhex(signature_dict["signature"]))
                sig_lengths.append(sig_length)

            # 3. 签名验证测试
            verify_times = []
            for _ in range(iterations):
                if algorithm == "SM2":
                    signature_dict = handler.sign(private_key, message, curve)
                else:
                    signature_dict = handler.sign(private_key, message)
                start_time = time.perf_counter()
                if algorithm == "SM2":
                    handler.verify(public_key, message, signature_dict, curve)
                else:
                    handler.verify(public_key, message, signature_dict)
                verify_times.append(time.perf_counter() - start_time)

            # 4. 计算统计结果
            result = {
                "algorithm": algorithm,
                "key_size": key_size if algorithm in ["RSA", "DSA"] else curve,
                "message_size": msg_size,
                "key_gen_time": {
                    "avg": np.mean(key_gen_times),
                    "min": np.min(key_gen_times),
                    "max": np.max(key_gen_times),
                    "std": np.std(key_gen_times)
                },
                "sign_time": {
                    "avg": np.mean(sign_times),
                    "min": np.min(sign_times),
                    "max": np.max(sign_times),
                    "std": np.std(sign_times)
                },
                "verify_time": {
                    "avg": np.mean(verify_times),
                    "min": np.min(verify_times),
                    "max": np.max(verify_times),
                    "std": np.std(verify_times)
                },
                "signature_length": {
                    "avg": np.mean(sig_lengths),
                    "min": np.min(sig_lengths),
                    "max": np.max(sig_lengths),
                    "std": np.std(sig_lengths)
                }
            }

            self.results.append(result)
            print(
                f"完成测试: {algorithm} | 密钥参数: {key_size if algorithm in ['RSA', 'DSA'] else curve} | 消息大小: {msg_size}B")

    def run_all_tests(self) -> None:
        """运行所有算法的完整性能测试"""
        # RSA测试配置
        for key_size in [1024, 2048, 4096]:
            self.run_test("RSA", key_size=key_size)

        # DSA测试配置
        for key_size in [1024, 2048, 3072]:
            self.run_test("DSA", key_size=key_size)

        # ECDSA测试配置
        for curve in ["P-256", "P-384"]:
            self.run_test("ECDSA", curve=curve)

        # SM2测试配置
        for curve in ["SECP256K1", "SECP256R1", "SECP384R1"]:
            self.run_test("SM2", curve=curve)  # SM2支持多曲线

    def export_results(self, filename: str = "signature_performance.json") -> None:
        """导出测试结果到JSON文件"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

    def get_summary(self) -> List[Dict[str, Any]]:
        """获取测试结果摘要"""
        summary = []
        for result in self.results:
            summary.append({
                "algorithm": result["algorithm"],
                "key_param": result["key_size"],
                "message_size": result["message_size"],
                "avg_key_gen_time_ms": round(result["key_gen_time"]["avg"] * 1000, 3),
                "avg_sign_time_ms": round(result["sign_time"]["avg"] * 1000, 3),
                "avg_verify_time_ms": round(result["verify_time"]["avg"] * 1000, 3),
                "avg_signature_length_bytes": round(result["signature_length"]["avg"], 1)
            })
        return summary

# ========== PQC算法 ==========
class PQCHandler:
    def __init__(self, alg="Dilithium2"):
        # Ensure we are using the module-level 'oqs'
        # This __init__ is expected to be called only if OQS_AVAILABLE is True,
        # meaning the module-level 'oqs' variable is the successfully imported module.
        if not OQS_AVAILABLE:
            # This case should ideally be prevented by the calling code (e.g., in gui_interface.py)
            # which checks OQS_AVAILABLE before instantiating PQCHandler.
            raise RuntimeError("PQCHandler instantiated but OQS is not available. "
                               "This indicates a logic error in the calling code.")
        
        # Assign the module-level 'oqs' to self.oqs for use in this instance.
        # 'oqs' here refers to the variable defined at the module level.
        self.oqs = oqs 
        self.alg = alg

        # The check now uses self.oqs (which refers to the module-level 'oqs').
        # If the module-level 'oqs' (which made OQS_AVAILABLE True) 
        # genuinely lacks 'get_enabled_sig_mechanisms', then the issue
        # lies with the installed 'oqs' library itself (e.g., version, corruption).
        
        # It's good practice to check for the attribute's existence before calling it,
        # especially if library versions might vary.
        if not hasattr(self.oqs, 'get_enabled_sig_mechanisms'):
            logger.error(
                "The 'oqs' module was imported (OQS_AVAILABLE is True), but it is missing the "
                "'get_enabled_sig_mechanisms' attribute. This strongly suggests an issue with "
                "the installed 'oqs' library (e.g., incorrect version or incomplete installation). "
                "Post-quantum cryptography features may not work as expected."
            )
            # Raising an AttributeError here makes the problem explicit.
            raise AttributeError(
                "The 'oqs' module is missing the 'get_enabled_sig_mechanisms' attribute. "
                "Please check your liboqs-python installation and version."
            )

        enabled_mechanisms = self.oqs.get_enabled_sig_mechanisms()
        if alg not in enabled_mechanisms:
            raise ValueError(f"OQS 库不支持算法: {alg}. 可用算法: {enabled_mechanisms}")

    def generate_keys_and_sign(self, message):
        with self.oqs.Signature(self.alg) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
            signature = signer.sign(message.encode())
        # 注意：secret_key 和 public_key 都是 bytes 类型
        # 为了兼容你的界面，返回 hex 字符串
        return secret_key.hex(), public_key.hex(), signature.hex()

    def verify(self, public_key, message, signature_hex):
        with self.oqs.Signature(self.alg) as verifier:
            signature = bytes.fromhex(signature_hex)
            public_key_bytes = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
            return verifier.verify(message.encode(), signature, public_key_bytes)

# ========== HMAC ==========
def hmac_sha256(key: bytes, message: str):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

# ========== PBKDF2 ==========
def derive_key(password: str, salt: bytes, length=32, iterations=100_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ========== AES-GCM加密私钥存储 ==========
def encrypt_private_key(private_key_bytes: bytes, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
    return salt + nonce + ciphertext

def decrypt_private_key(encrypted: bytes, password: str):
    salt = encrypted[:16]
    nonce = encrypted[16:28]
    ciphertext = encrypted[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def save_private_key_encrypted(private_key_bytes, filename, password):
    encrypted = encrypt_private_key(private_key_bytes, password)
    with open(filename, "wb") as f:
        f.write(encrypted)

def load_private_key_encrypted(filename, password):
    with open(filename, "rb") as f:
        encrypted = f.read()
    return decrypt_private_key(encrypted, password)