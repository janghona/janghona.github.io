
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

# Generate a key pair
private_key = ECC.generate(curve='secp256r1')
public_key = private_key.public_key()

# Sign a message
message = b"Hello, World!"
h = SHA256.new(message)
signer = DSS.new(private_key, 'fips-186-3')
signature = signer.sign(h)

# Verify the signature
verifier = DSS.new(public_key, 'fips-186-3')
h = SHA256.new(message)
try:
    verifier.verify(h, signature)
    print("Signature is valid.")
except ValueError:
    print("Signature is not valid.")