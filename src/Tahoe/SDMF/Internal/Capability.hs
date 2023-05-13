-- | Structured representations of SDMF capabilities.
module Tahoe.SDMF.Internal.Capability where

import Prelude hiding (Read)

import qualified Data.ByteString as B
import Tahoe.SDMF.Internal.Keys (Read, Write, deriveReadKey)

-- | A read capability for an SDMF object.
data Reader = Reader
    { readerReadKey :: Read
    , readerVerificationKeyHash :: B.ByteString
    }
    deriving (Show)

-- | A write capability for an SDMF object.
data Writer = Writer
    { writerWriteKey :: Write
    , writerReader :: Reader
    }
    deriving (Show)

-- | Diminish a write key to a read key and wrap it in a reader capability.
deriveReader :: Write -> B.ByteString -> Maybe Reader
deriveReader w fingerprint = Reader <$> deriveReadKey w <*> pure fingerprint
