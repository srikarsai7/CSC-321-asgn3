from Crypto.Util import number

# Support variable-length primes (up to 2048 bits)
def generate_prime(bits):
    """Generate a prime number with the specified number of bits."""
    return number.getPrime(bits)

# Modular inverse calculation using Extended Euclidean Algorithm
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
    
# Generate RSA key pair
def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (n, e), (n, d)

# Encrypt using RSA
def encrypt(message, public_key):
    n, e = public_key
    return pow(message, e, n)

# Decrypt using RSA
def decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)

# Sign using RSA
def sign(message, private_key):
    n, d = private_key
    return pow(message, d, n)

# Verify a signature using RSA
def verify(message, signature, public_key):
    n, e = public_key
    return pow(signature, e, n) == message

# Helper functions for converting strings to integers and vice versa
def string_to_int(message):
    hex_string = message.encode().hex()
    return int(hex_string, 16)

def int_to_string(number):
    hex_string = hex(number)[2:]  # Remove '0x' prefix
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Ensure even length
    return bytes.fromhex(hex_string).decode()

def main():
    print("Part 1: RSA Malleabilty Attack")

    # task 3 part 1: RSA Malleabilty Attack
    bob_pub, bob_priv = generate_keypair(2048)
    alice_pub, alice_private_key = generate_keypair(2048)

    s = 1223456
    print("Alice s value:", s)

    bob_c = encrypt(s, alice_pub)
    print ("bob_c:", bob_c)

    # Mallory intercepts the message
    k = 2
    bob_c0 = (bob_c * pow(k, alice_pub[1], alice_pub[0])) % alice_pub[0]
    print("mallory intercepts. using k = 2, bob_c0 is now:", bob_c0)

    # Decrypts the modified ciphertext
    s0 = decrypt(bob_c0, alice_private_key)
    print("Decrypted symmetric key from Alice:", s0)

    s_ded = s0//k
    print("Mallory symmetric key:", s_ded)

    if s == s_ded:
        print("Mallory recovered the s value")

    print("\n")
    print("Part 2: Signature malleabilty Attack")
    # bob signs two msgs m1 and m2
    mess1 = string_to_int("Hi Alice")
    mess2 = string_to_int("Hi Bob")
    sign1 = sign(mess1, bob_priv)
    sign2 = sign(mess2, bob_priv)
    mess3 = (mess1 * mess2) % bob_pub[0]
    sign3 = (sign1 * sign2) % bob_pub[0]
    print("message 3:", mess3)
    print("Signature by Mallory:", sign3)
    if verify(mess3, sign3, bob_pub):
        print("Signature forged by mallory")
    else:
        print("Signature was not forged by mallory")

main()