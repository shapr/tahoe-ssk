module Tahoe.SDMF.Internal.Keys where

import Prelude hiding (Read)

import Codec.Crypto.RSA (generateKeyPair)
import Crypto.Cipher.AES128 (AESKey128)
import qualified Crypto.PubKey.RSA.Types as RSA
import "crypto-api" Crypto.Random (SystemRandom, newGenIO)
import qualified Data.ByteString as B
import Tahoe.CHK.Server (StorageServerID)

newtype Pair = Pair {unPair :: RSA.KeyPair}
newtype Verification = Verification {unVerification :: RSA.PublicKey}
newtype Signature = Signature {unSignature :: RSA.PrivateKey}
newtype Write = Write {unWrite :: AESKey128}
newtype Read = Read {unRead :: AESKey128}
newtype StorageIndex = StorageIndex {unStorageIndex :: B.ByteString}

newtype WriteEnablerMaster = WriteEnablerMaster B.ByteString
data WriteEnabler = WriteEnabler StorageServerID B.ByteString

newtype Encryption = Encryption AESKey128

-- | The size of the keys to generate.
bits :: Int
bits = 2048

{- | Create a new, random key pair (public/private aka verification/signature)
 of the appropriate type and size for SDMF encryption.
-}
newKeyPair :: IO Pair
newKeyPair = do
    g <- newGenIO :: IO SystemRandom
    let (_, priv, _) = generateKeyPair g bits
    pure . Pair . RSA.KeyPair $ priv

-- | Compute the write key for a given signature key for an SDMF share.
deriveWriteKey :: Signature -> Maybe Write
deriveWriteKey = buildKey . taggedHash writeKeyLength mutableWriteKeyTag . signatureKeyToBytes . unSignature

-- | Compute the read key for a given signature key for an SDMF share.
deriveReadKey :: Write -> Maybe Read
deriveReadKey = buildKey . taggedHash readKeyLength mutableReadKeyTag . encode . unWrite
