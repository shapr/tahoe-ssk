# Changelog for tahoe-ssk

## 0.3.0.0 (Unreleased)

* Updated the tahoe-chk dependency to 0.2.0.0.

## 0.2.1.0

* Add Ord instances for StorageIndex, Verifier, Reader, and Writer.
* Add ConfidentialShowable instances for SDMF, Verifier, Reader, and Writer.
* Deprecate dangerRealShow.

## 0.2.0.0

* Add the IV as a parameter to Tahoe.SDMF.encode.
  The IV must be the value used to create the ciphertext so Tahoe.SDMF.encode cannot randomly generate one.
* Add Tahoe.SDMF.randomIV for randomly generating a new IV.

## 0.1.0.0

* Initial release.
* Very basic non-verifying decoding support.
* Enough encoding support for simple round-trip tests for the decoding functionality.
