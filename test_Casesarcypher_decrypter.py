# python -m unittest test_Casesarcypher_decrypter.py
import unittest
from Caesarcypher_decrypter import caesar_shift, brute_force_decrypt, best_guess_decrypt

class TestCaesarCracker(unittest.TestCase):
    def test_shift_roundtrip(self):
        text = "Hello, World!"
        for k in range(26):
            enc = caesar_shift(text, k)
            dec = caesar_shift(enc, -k)
            self.assertEqual(dec, text)

    def test_bruteforce_contains_original(self):
        plaintext = "attack at dawn"
        ciphertext = caesar_shift(plaintext, 5)
        results = brute_force_decrypt(ciphertext)
        # key=5 decryption should equal plaintext
        self.assertIn((5, plaintext), results)

    def test_best_guess(self):
        plaintext = "this is a secret message"
        ciphertext = caesar_shift(plaintext, 7)
        guess = best_guess_decrypt(ciphertext, top_n=1)[0]
        # The top candidate's plaintext should match original for reasonably long text
        self.assertEqual(guess[1], plaintext)

if __name__ == "__main__":
    unittest.main()
