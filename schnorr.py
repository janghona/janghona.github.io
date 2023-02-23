
from Crypto.Util.number import inverse
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC

# Generate the Schnorr signature
def schnorr_sign(privkey, message):
    hash = SHA256.new(message)
    k = ECC.generate(curve='secp256r1').d % privkey.curve.order
    R = k * privkey.public_key()
    r = int.from_bytes(R.x.to_bytes(), byteorder='big')
    e = int.from_bytes(hash.digest(), byteorder='big')
    s = (k + e * privkey.secret) % privkey.curve.order
    return (r, s)

# Verify the Schnorr signature
def schnorr_verify(pubkey, message, signature):
    hash = SHA256.new(message)
    r, s = signature
    if r < 1 or r >= pubkey.curve.order or s < 1 or s >= pubkey.curve.order:
        return False
    e = int.from_bytes(hash.digest(), byteorder='big')
    w = inverse(s, pubkey.curve.order)
    u1 = (e * w) % pubkey.curve.order
    u2 = (r * w) % pubkey.curve.order
    R = u1 * pubkey.public_key() + u2 * pubkey.point
    if R == ECC.PointJacobi(pubkey.curve):
        return False
    return (r == R.x % pubkey.curve.order)
