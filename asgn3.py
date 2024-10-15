import random
import os
from hashlib import sha256
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad

q = int("""
B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61
6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF
ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0
A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
""".replace("\n", ""), 16)

a = int("""
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31
266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4
D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A
D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
""".replace("\n", ""), 16)

#a = q - 1

def generate_private_key():
    return random.randint(2, q-2)

def compute_public_key(priv_key):
    return pow(a, priv_key, q)

def compute_shared_secret(public_key, priv_key):
    return pow(public_key, priv_key, q)

def derive_key(secret):
    secret_bytes = str(secret).encode('utf-8')
    return sha256(secret_bytes).digest()[:16]

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return decrypted.decode('utf-8')

def diffie_hellman_protocol():
    alice_priv = generate_private_key()
    alice_pub = compute_public_key(alice_priv)

    bob_priv = generate_private_key()
    bob_pub = compute_public_key(bob_priv)

    alice_secret = compute_shared_secret(alice_pub, bob_priv)
    bob_secret = compute_shared_secret(bob_pub, alice_priv)

    if alice_secret != bob_secret:
        print("Shared secret mismatch")
    
    symmetric_key = derive_key(alice_secret)

    encrypted = encrypt_message(symmetric_key, "Hi Bob!")
    print("(task 1) Encrypted message: ", encrypted)

    decrypted = decrypt_message(symmetric_key, encrypted)
    print("(task 1) Decrypted message: ", decrypted)

    encrypted = encrypt_message(symmetric_key, "Hi Alice!")
    print("(task 1) Encrypted message: ", encrypted)

    decrypted = decrypt_message(symmetric_key, encrypted)
    print("(task 1) Decrypted message: ", decrypted)


    # task 2

    mallory_priv = generate_private_key()
    mallory_pub = compute_public_key(mallory_priv)

    symmetric_key = derive_key(0)

    encrypted_alice = encrypt_message(symmetric_key, "hello bob!")
    decrypted_alice = decrypt_message(symmetric_key, encrypted_alice)

    print(f"encrypted message by alice {encrypted_alice}")
    print(f"decrypted message by alice {decrypted_alice}")

    alice_priv = generate_private_key()
    alice_pub = compute_public_key(alice_priv)

    bob_priv = generate_private_key()
    bob_pub = compute_public_key(bob_priv)

    alice_secret = compute_shared_secret(q, bob_priv)
    bob_secret = compute_shared_secret(q, alice_priv)


    if alice_secret != bob_secret:
        print("Shared secret mismatch")
    
    symmetric_key = derive_key(alice_secret)

    encrypted = encrypt_message(symmetric_key, "Hi Bob!")
    #print("Encrypted message: ", encrypted)

    decrypted = decrypt_message(symmetric_key, encrypted)
    #print("Decrypted message: ", decrypted)

    encrypted = encrypt_message(symmetric_key, "Hi Alice!")
    #print("Encrypted message: ", encrypted)

    decrypted = decrypt_message(symmetric_key, encrypted)
    #print("Decrypted message: ", decrypted)

diffie_hellman_protocol()