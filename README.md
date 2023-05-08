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
