import os

def generate_key():
    # Always generate 256-bit keys for simplicity; AES-128 can just fold them in half.
    return os.urandom(32)

def _xor_bytes(a, b):
    assert(len(a) == len(b))
    return bytes([ax ^ bx for ax, bx in zip(a, b)])

def _fold_key(buf):
    assert(len(buf) == 32)
    return _xor_bytes(buf[:16], buf[16:])
