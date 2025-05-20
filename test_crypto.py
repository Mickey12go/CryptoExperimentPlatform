import unittest
from crypto_algorithms import RSAHandler, DSAHandler, ECDSAHandler, SM2Handler


class TestCryptoAlgorithms(unittest.TestCase):
    def test_rsa(self):
        rsa_handler = RSAHandler()
        private_key, public_key = rsa_handler.generate_keys()
        message = "Test message"
        signature = rsa_handler.sign(private_key, message)
        result = rsa_handler.verify(public_key, message, signature)
        self.assertTrue(result)

    def test_dsa(self):
        dsa_handler = DSAHandler()
        private_key, public_key = dsa_handler.generate_keys()
        message = "Test message"
        signature = dsa_handler.sign(private_key, message)
        result = dsa_handler.verify(public_key, message, signature)
        self.assertTrue(result)

    def test_ecdsa(self):
        ecdsa_handler = ECDSAHandler()
        private_key, public_key = ecdsa_handler.generate_keys()
        message = "Test message"
        signature = ecdsa_handler.sign(private_key, message)
        result = ecdsa_handler.verify(public_key, message, signature)
        self.assertTrue(result)

    def test_sm2_keygen(self):
        handler = SM2Handler()
        private, public = handler.generate_keys()
        self.assertEqual(len(private),64)
        self.assertEqual(len(public),130)
        self.assertTrue(public.startswith('04'))
        #添加格式验证
        self.assertTrue(all(c in '0123456789abcdef' for c in public[2:]))

    def test_rsa_different_key_size(self):
        rsa_handler = RSAHandler()
        private_key, public_key = rsa_handler.generate_keys(key_size=1024)
        message = "Another Test message"
        signature = rsa_handler.sign(private_key, message)
        result = rsa_handler.verify(public_key, message, signature)
        self.assertTrue(result)

    def test_dsa_different_message(self):
        dsa_handler = DSAHandler()
        private_key, public_key = dsa_handler.generate_keys()
        message = "This is a different message"
        signature = dsa_handler.sign(private_key, message)
        result = dsa_handler.verify(public_key, message, signature)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()