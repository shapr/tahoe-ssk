# tahoe-ssk

## What is it?

Tahoe-SSK is a Haskell implementation of the [Tahoe-LAFS](https://tahoe-lafs.org/) SSK crytographic protocols.
This includes (S)mall (D)istributed (M)utable (F)iles (SDMF) and (M)edium (D)istributed (M)utable (F)iles (MDMF).
It aims for bit-for-bit compatibility with the original Python implementation.

It will not include an implementation of any network protocol for transferring SSK shares.
However, its APIs are intended to be easy to integrate with such an implementation.

### What is the current state?

* All implementation tasks are pending.

## Why does it exist?

A Haskell implementation can be used in places the original Python implementation cannot be
(for example, runtime environments where it is difficult to have a Python interpreter).
Additionally,
with the benefit of the experience gained from creating and maintaining the Python implementation,
a number of implementation decisions can be made differently to produce a more efficient, more flexible, simpler implementation and API.
Also,
the Python implementation claims no public library API for users outside of the Tahoe-LAFS project itself.

## Cryptographic Library Choice

This library uses cryptonite for cryptography,
motivated by the following considerations.

SDMF uses
* SHA256 for tagged hashes for key derivation and for integrity (XXX right word?) checks on some data.
* AES128 for encryption of the signature key and the application plaintext data.
* RSA for signatures proving write authority.

There are a number of Haskell libraries that provide all of these:

* Crypto
  * Does not support the AES mode we require (CTR).

* HsOpenSSL
  * Bindings to a C library, OpenSSL, which may complicate the build process.
  * OpenSSL's security and reliability track record also leaves something to be desired.

* cryptonite
  * Has all of the primitive cryptographic functionality we need.

We want a library that:

* Can be used with reflex-platform
  * ghc 8.6.5 compatible
* Can be cross-compiled to different targets from x86_64-linux
  * Mainly armeabi and armv7
* Is suitable for real-world security purposes
  * not a demo or a toy library
  * avoids real-world pitfalls (side-channel attacks, etc), not just textbook issues
  * has more than a handful of other users

### SHA256

There are a number of Haskell libraries that provide this primitive:

* Crypto
* HsOpenSSL
* SHA
* cryptohash
* cryptonite
* dhall
* hashing
* nettle
* sbv
* tls

### AES128

* Crypto
* HsOpenSSL
* cipher-aes
* cipher-aes128
* crypto
* cryptocipher
* cryptonite
* cryptostore
* nettle

### RSA

SDMF depends on RSA for signatures proving write authority.

* Crypto
* HsOpenSSL
* RSA
* cryptonite
