# Tested on Python 3.9.15 against Tahoe-LAFS bc79cf0a11f06bbdc02a5bb41c6f41fcff727ea5
#

from allmydata.crypto import rsa
from allmydata.mutable.common import derive_mutable_keys
from allmydata.util import base32
from allmydata.util.hashutil import (
    ssk_readkey_hash,
    ssk_readkey_data_hash,
    ssk_storage_index_hash,
)

# Arbitrarily select an IV.
iv = b"\x42" * 16

with open("data/rsa-privkey-0.der", "rb") as f:
    (priv, pub) = rsa.create_signing_keypair_from_string(f.read())

writekey, encprivkey, fingerprint = derive_mutable_keys((pub, priv))
readkey = ssk_readkey_hash(writekey)
datakey = ssk_readkey_data_hash(iv, readkey)
storage_index = ssk_storage_index_hash(readkey)

print("SDMF")
print("writekey: ", base32.b2a(writekey))
print("readkey: ", base32.b2a(readkey))
print("datakey: ", base32.b2a(datakey))
print("storage index: ", base32.b2a(storage_index))
print("encrypted private key: ", base32.b2a(encprivkey))
print("signature key hash: ", base32.b2a(fingerprint))

(priv, pub) = rsa.create_signing_keypair(2048)
priv_bytes = rsa.der_string_from_signing_key(priv)
with open("data/tahoe-lafs-generated-rsa-privkey.der", "wb") as f:
    f.write(priv_bytes)
