from sage.all import *

# Step 1: NIST P-384 domain parameters
p = 2^384 - 2^128 - 2^96 + 2^32 - 1
a = -3
b = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
        "c656398d8a2ed19d2a85c8edd3ec2aef", 16)

Gx = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
         "5502f25dbf55296c3a545e3872760ab7", 16)

Gy = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
         "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16)

n = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973", 16)

F = FiniteField(p)
E = EllipticCurve(F, [F(a), F(b)])
G = E(F(Gx), F(Gy))

print("Curve and base point successfully defined.")

# Step 2: Key generation
d = randint(1, n - 1)  # Private key
Q = d * G               # Public key

# Print the used parameters
print("\nUsed Parameters:")
print(f"p (prime): {p}")
print(f"a (curve coefficient): {a}")
print(f"b (curve coefficient): {b}")
print(f"Base point G: {G}")
print(f"Base point order n: {n}")
print(f"Private key d: {d}")
print(f"Public key Q: {Q}")

# Step 3: Message hashing (SHA-384)
import hashlib

def hash_message(message):
    """Hashes the message using SHA-384 and returns an integer."""
    digest = hashlib.sha384(message).digest()
    return Integer(digest.hex(), 16) % n

# Step 4: Signature generation
def generate_signature(message, private_key):
    """Generates a valid signature for the given message and private key."""
    m = hash_message(message)
    
    r = 0
    s = 0
    # Try different k values until r != 0 and s != 0
    while r == 0 or s == 0:
        k = randint(1, n - 1)
        R = k * G
        r = Integer(R[0]) % n
        if r != 0:
            k_inv = inverse_mod(k, n)
            s = (k_inv * (m + r * private_key)) % n
            # exit loop when r and s are valid
    
    return (r, s)

# Step 5: Signature verification
def verify_signature(message, signature, public_key):
    """Verifies the signature for a given message and public key."""
    r, s = signature
    print(f"\nVerifying signature for message: {message}")
    print(f"Signature: (r = {r}, s = {s})")
    print(f"Public key Q: {public_key}")
    
    if r <= 0 or r >= n or s <= 0 or s >= n:
        print("Invalid signature: r or s out of range")
        return False

    w = inverse_mod(s, n)
    m = hash_message(message)
    u1 = (m * w) % n
    u2 = (r * w) % n
    P = u1 * G + u2 * public_key
    v = Integer(P[0]) % n

    print(f"Computed v: {v}, expected r: {r}")

    return v == r

# Step 6: Test Cases

# 1. Valid Signature
message = b"Hello from SageMath using NIST P-384!"
valid_signature = generate_signature(message, d)
print("\nValid signature test:")
print("Signature valid:", verify_signature(message, valid_signature, Q))

# 2. Invalid Signature due to different message
invalid_message = b"Hello from SageMath with a different message!"
print("\nInvalid signature test (different message):")
print("Signature valid:", verify_signature(invalid_message, valid_signature, Q))

# 3. Invalid Signature due to different public key
# Let's create a different public key
different_private_key = randint(1, n - 1)
different_public_key = different_private_key * G
print("\nInvalid signature test (different public key):")
print("Signature valid:", verify_signature(message, valid_signature, different_public_key))

# 4. Invalid Signature due to different signature
# Let's generate a different signature
different_signature = generate_signature(message, different_private_key)
print("\nInvalid signature test (different signature):")
print("Signature valid:", verify_signature(message, different_signature, Q))
