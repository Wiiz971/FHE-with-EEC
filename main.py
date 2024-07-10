####################################################
#              Importation de modules              #
####################################################
#https://www.secg.org/sec2-v2.pdf
from py_ecc.bn128 import G1, add, multiply, curve_order, is_on_curve, FQ
from hashlib import sha256
import secrets
import json
from typing import Optional, List, Tuple
import galois
import time
 
class DataAnonymizerFHE:
    def __init__(self):
        """
        Initialize the DataAnonymizerFHE class.
        """
        self.private_key = None
        self.public_key = None
        a = time.time()
        print("Initialisation ...")
        self.GF = galois.GF(curve_order)  # Instance of Galois Field (GF(p) where p=21888242871839275222246405745257275088548364400416034343698204186575808495617)
        b = time.time()
        print("Fin de l'instanciation ...")
        print (f"GF Runtime : {int((diff := b - a) // 60)} min et {int(diff % 60)} sec")
 
    def keygen(self, force: bool = False, seed: Optional[int] = None, encryption_seed: Optional[int] = None):
        """
        Generate keys required for homomorphic evaluation.

        @param force: bool, default=False, whether to generate new keys even if keys are already generated
        @param seed: Optional[int], default=None, seed for private keys randomness
        @param encryption_seed: Optional[int], default=None, seed for encryption randomness
        """
        if self.private_key is not None and not force:
            print("Keys are already generated. Use force=True to regenerate.")
            return
        
        if seed is not None:
            secrets_generator = secrets.SystemRandom(seed)
            self.private_key = secrets_generator.randint(1, curve_order - 1)
        else:
            self.private_key = secrets.randbelow(curve_order)
        print(self.private_key)
        A = self.GF(3)

        print(type(self.private_key))
        # Convert private key to FQ element for operations
        self.private_key = self.GF(int(self.private_key))
        print(self.private_key)
        print(type(self.private_key))

        #if not is_on_curve(self.private_key, G1):
        if is_on_curve(G1,self.private_key) is False:
            raise ValueError("Generated private key is not on the curve")

        # Generate public key
        self.public_key = multiply(G1, self.private_key)

        # Verify if public key is on the curve
        if not is_on_curve(self.public_key, G1):
            raise ValueError("Generated public key is not on the curve")
        

    def encrypt(self, plaintext: str, encryption_seed: Optional[int] = None) -> Tuple[Tuple[int, int], int]:
        """
        Encrypt the plaintext using the public key.

        @param plaintext: str, the plaintext to encrypt
        @param encryption_seed: Optional[int], default=None, seed for encryption randomness
        @return: Tuple[Tuple[int, int], int], the encrypted ciphertext as a tuple of elliptic curve point and integer
        """
        if self.public_key is None:
            raise ValueError("Keys are not generated. Please run keygen() first.")
       
        # Convert plaintext to bytes and then to integer
        plaintext_bytes = plaintext.encode('utf-8')
        plaintext_int = int.from_bytes(plaintext_bytes, byteorder='big') % curve_order
        plaintext_gf = self.GF(plaintext_int)
 
        # Generate ephemeral key
        if encryption_seed is not None:
            secrets_generator = secrets.SystemRandom(encryption_seed)
            ephemeral_key = self.GF(secrets_generator.randint(1, curve_order - 1))
        else:
            ephemeral_key = self.GF(secrets.randbelow(curve_order))
       
        shared_key = multiply(self.public_key, int(ephemeral_key))
       
        # Encrypt the plaintext
        ciphertext_c1 = multiply(G1, int(ephemeral_key))
        ciphertext_c2 = self.GF(int(shared_key[0])) + plaintext_gf
        ciphertext_c2 = int(ciphertext_c2) % curve_order  # Convert back to int and mod curve_order
 
        ciphertext = (ciphertext_c1, ciphertext_c2)
        return ciphertext
 
    def decrypt(self, ciphertext: Tuple[Tuple[int, int], int]) -> str:
        """
        Decrypt the ciphertext using the private key.
 
        @param ciphertext: Tuple[Tuple[int, int], int], the encrypted ciphertext as a tuple of elliptic curve point and integer
        @return: str, the decrypted plaintext
        """
        if self.private_key is None:
            raise ValueError("Keys are not generated. Please run keygen() first.")
   
        c1, c2 = ciphertext
        shared_key = multiply(c1, int(self.private_key))
        plaintext_int = self.GF(c2) - self.GF(int(shared_key[0]))
 
        # Convert integer back to bytes and then to string
        plaintext_bytes = int(plaintext_int).to_bytes((int(plaintext_int).bit_length() + 7) // 8, byteorder='big')
        plaintext = plaintext_bytes.decode('utf-8', errors='ignore')
        return plaintext
 
    def homomorphic_addition(self, ciphertexts: List[Tuple[Tuple[int, int], int]]) -> Tuple[Tuple[int, int], int]:
        """
        Perform homomorphic addition on a list of ciphertexts.
 
        @param ciphertexts: List[Tuple[Tuple[int, int], int]], a list of ciphertexts
        @return: Tuple[Tuple[int, int], int], the result of the homomorphic addition as a tuple of elliptic curve point and integer
        """
        sum_c1 = None
        sum_c2 = self.GF(0)
 
        for c1, c2 in ciphertexts:
            if sum_c1 is None:
                sum_c1 = c1
                print(f"le sum_c1 est {sum_c1}")
            else:
                sum_c1 = add(sum_c1, c1)

            sum_c2 += self.GF(c2)
            print(f"le sum_c2 est {sum_c2}")
        return (sum_c1, int(sum_c2))
 
    def save_keys(self, filepath: str):
        """
        Save the keys to a file.
 
        @param filepath: str, the file path to save the keys to
        """
        keys = {
            "private_key": int(self.private_key),
            "public_key": [int(self.public_key[0]), int(self.public_key[1])]  # Convert to int for serialization
        }
        with open(filepath, 'w') as file:
            json.dump(keys, file)
 
    def load_keys(self, filepath: str):
        """
        Load the keys from a file.
 
        @param filepath: str, the file path to load the keys from
        """
        with open(filepath, 'r') as file:
            keys = json.load(file)
            self.private_key = self.GF(keys['private_key'])
            self.public_key = (self.GF(keys['public_key'][0]), self.GF(keys['public_key'][1]))

        # Convert the public key back to the format used by py_ecc
        public_key_point = (FQ(self.public_key[0]), FQ(self.public_key[1]), FQ(self.public_key[2]))

        # Verify that the point is on the curve
        if not is_on_curve(public_key_point, G1):
            raise ValueError("Loaded public key is not on the curve")

 
if __name__ == "__main__":
    # Example usage
    anonymizer = DataAnonymizerFHE()
 
    # Generate keys with seeds
    anonymizer.keygen(force=True, seed=42, encryption_seed=11)
 
    # Encrypt multiple plaintexts
    plaintexts = ["Hello, World!", "Kevin", "This is a test."]
    ciphertexts = [anonymizer.encrypt(text, encryption_seed=11 + i) for i, text in enumerate(plaintexts)]
 
    # Display encrypted texts
    for i, ciphertext in enumerate(ciphertexts):
        print(f"Ciphertext {i}: {ciphertext}")
 
    # Homomorphic addition of encrypted texts
    homomorphic_ciphertext = anonymizer.homomorphic_addition(ciphertexts)
    print(f"Homomorphic Ciphertext: {homomorphic_ciphertext}")
 
    # Decrypt the result of homomorphic addition
    homomorphic_plaintext = anonymizer.decrypt(homomorphic_ciphertext)
    print(f"Result of homomorphic addition: '{homomorphic_plaintext}'")
 
    # Save keys to a file
    anonymizer.save_keys('keys.json')
 
    # Load keys from a file
    anonymizer.load_keys('keys.json')
