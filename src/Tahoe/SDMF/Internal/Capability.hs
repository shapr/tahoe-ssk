module Tahoe.SDMF.Internal.Capability where

import Crypto.Cipher.AES128 (AESKey128)
import qualified Data.ByteString as B
import Data.Serialize (encode)
import Tahoe.CHK.Crypto (taggedHash)

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
