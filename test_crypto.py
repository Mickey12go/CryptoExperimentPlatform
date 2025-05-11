import unittest
from inspect import signature

from Crypto.SelfTest.Protocol.test_ecdh import private_key, public_key
from pyexpat.errors import messages

from crypto_algorithms import RSAHandler,DSAHandler,ECDSAHandler,SM2Handler

class TestCrytoAlgorithms(unittest.TestCase):
    def test_rsa(self):
        rsa_handler=RSAHandler()
        private_key,public_key=rsa_handler.generate_keys()
        message="Test message"
        signature=rsa_handler.sign(private_key,message)
        result=rsa_handler.verify(public_key,message,signature)
        self.assertEqual(result,True)

    def test_dsa(self):
        dsa_handler=DSAHandler()
        private_key,public_key=dsa_handler.generate_keys()
        message="Test message"
        signature=dsa_handler.sign(private_key,message)
        result=dsa_handler.verify(public_key,message,signature)
        self.assertEqual(result,True)

    def test_ecdsa(self):
        ecdsa_handler=ECDSAHandler()
        private_key, public_key = ecdsa_handler.generate_keys()
        message = "Test message"
        signature = ecdsa_handler.sign(private_key, message)
        result = ecdsa_handler.verify(public_key, message, signature)
        self.assertEqual(result, True)

    def test_sm2(self):
        sm2_handler=SM2Handler()
        private_key, public_key = sm2_handler.generate_keys()
        message = "Test message"
        signature = sm2_handler.sign(private_key, message)
        result = sm2_handler.verify(public_key, message, signature)
        self.assertEqual(result, True)

if __name__=="__main__"
    unittest.main()