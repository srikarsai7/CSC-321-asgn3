import random
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

q = int("""
B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61
6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF
ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0
A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
""".replace("\n", ""), 16)

'''a = int("""
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31
266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4
D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A
D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
""".replace("\n", ""), 16)'''

a = q

# Requirement: Support variable length primes (up to 2048 bits)
def generate_prime(bits):
    """Generate a prime number with the specified number of bits."""
    return number.getPrime(bits)

def mod_inverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m."""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m
    
# Requirement: Implement key generation
def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Requirement: Use the value e=65537
    d = mod_inverse(e, phi)
    d_check = pow(e, -1, phi)
    #print(f"\nmod_inverse_check (d): {d}")
    #print(f"pow (d_check): {d_check}\n")
    return ((n, e), (n, d)) 

# Requirement: Implement encryption
def encrypt(public_key, message):
    """Encrypt a message using RSA."""
    n, e = public_key
    return pow(message, e, n)

# Requirement: Implement decryption
def decrypt(private_key, ciphertext: int):
    """Decrypt a ciphertext using RSA."""
    n = private_key[0]
    d = private_key[1]
    # print(f"n: {n}, d: {d}, c: {ciphertext}")
    result = pow(ciphertext, d, n)
    return result

# Requirement: Convert ASCII string to hex, then to integer
def string_to_int(message):
    """Convert an ASCII string to an integer via hex."""
    hex_string = message.encode().hex()
    return int(hex_string, 16)

def int_to_string(number):
    """Convert an integer back to an ASCII string."""
    hex_string = hex(number)[2:]  # Remove '0x' prefix
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Ensure even length
    return bytes.fromhex(hex_string).decode()

def private_key():
    return random.randint(2, q-2)

def public_key(priv_key):
    return pow(a, priv_key, q)

def shared_secret(public_key, priv_key):
    return pow(public_key, priv_key, q)

def dkey(secret):
    secret_bytes = str(secret).encode('utf-8')
    return sha256(secret_bytes).digest()[:16]

def enc_mess(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv + ciphertext

def dec_mess(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return decrypted.decode('utf-8')

def dhp():
    a_priv = private_key()
    a_pub = public_key(a_priv)

    b_priv = private_key()
    b_pub = public_key(b_priv)

    a_sec = shared_secret(q, a_priv)
    b_sec = shared_secret(q, b_priv)


    if a_sec != b_sec:
        print("Shared secret mismatch")
    
    sym_key = dkey(a_sec)

    enc = enc_mess(sym_key, "I like red")
    print("Encrypted message: ", enc)

    dec = dec_mess(sym_key, enc)
    print("Decrypted message: ", dec)

    enc = enc_mess(sym_key, "I like blue")
    print("Encrypted message: ", enc)

    dec = dec_mess(sym_key, enc)
    print("Decrypted message: ", dec)

dhp()

keys = generate_keypair(16)
ciphertext = encrypt(keys[0], string_to_int("hi my name is molly"))
plaintext = decrypt(keys[1], ciphertext)
print(ciphertext)
print(plaintext)

### task 3
m = "Hello, alice!"
# alice generates an RSA key pair
alice_keys = generate_keypair(8)
print (f"\nAlice's public key: {alice_keys[0]}\nAlice's private key: {alice_keys[1]}")
# alice computes s and c: 
#   s = random prime and c = s^e mod n
s = generate_prime(8)
e = alice_keys[0][1]
n = alice_keys[0][0]
d = alice_keys[1][1]
c = pow(s, e, n)

# Mallory Intercepts and Modifies c: 
#   Mallory intercepts c and calculates c' = (c * pow(factor, e, n)) % n using a random integer factor coprime to n.
factor = 2
c_prime = (c * pow(factor, e, n)) % n
print(f"\nMallory's modified ciphertext (c'): {c_prime}")
# Bob Computes s': 
#   Bob receives c' and decrypts it using Alice's private key to obtain s'.
s_prime = pow(c_prime, d, n)
# Mallory Recovers s:
#    Mallory uses s_mallory = (s_prime * pow(factor, -1, n)) % n to recover the original s.
s_mallory =  s_prime * (pow(factor, -1, n))
print(f"\nMallory's recovered s: {s_mallory}, original s: {s}")
# Alice uses s to encrypt message m:
c0 = encrypt((n, e), string_to_int(m))
# Alice sends c0 to Bob and Mallory intercepts it.
# Mallory uses c0 and recovers the original message m:
#   Mallory calculates k_mallory = sha256(s_mallory) and decrypts c0 using k_mallory to recover the original message m.

recovered_m = decrypt((n, s_mallory), c0)
print("original message: ", m)
print("recovered message: ", int_to_string(int(recovered_m)))
