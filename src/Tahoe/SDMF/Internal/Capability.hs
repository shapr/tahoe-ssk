module Tahoe.SDMF.Internal.Capability where

import Crypto.Cipher.AES128 (AESKey128)
import Crypto.Classes (buildKey)
import Crypto.Types (IV)
import qualified Data.ByteString as B
import Data.Serialize (encode)
import Tahoe.CHK.Crypto (taggedHash, taggedPairHash)

data Reader = Reader
    { readerReadKey :: B.ByteString
    , readerVerificationKeyHash :: B.ByteString
    }

data Writer = Writer
    { writerWriteKey :: AESKey128
    , writerReader :: Reader
    }

deriveReader :: AESKey128 -> B.ByteString -> Reader
deriveReader writeKey readerVerificationKeyHash = Reader{..}
  where
    readerReadKey = taggedHash readKeyLength mutableReadKeyTag (encode writeKey)

readKeyLength :: Int
readKeyLength = 32

mutableReadKeyTag :: B.ByteString
mutableReadKeyTag = "allmydata_mutable_writekey_to_readkey_v1"

{- | Compute the encryption (and decryption) key used to convert the
 application payload plaintext to ciphertext and back again.
-}
deriveEncryptionKey :: MonadFail m => Reader -> IV AESKey128 -> m AESKey128
deriveEncryptionKey Reader{readerReadKey} iv = do
    let k = buildKey $ taggedPairHash encryptionKeyLength mutableDataKeyTag readerReadKey (encode iv)
    case k of
        Nothing -> fail "Could not build AESKey128 when deriving encryption key"
        Just key -> pure key

mutableDataKeyTag :: B.ByteString
mutableDataKeyTag = "allmydata_mutable_readkey_to_datakey_v1"

encryptionKeyLength :: Int
encryptionKeyLength = 16
