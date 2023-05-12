-- | Structured representations of SDMF capabilities.
module Tahoe.SDMF.Internal.Capability where

import Prelude hiding (Read)

import qualified Data.ByteString as B
import Tahoe.SDMF.Internal.Keys (Read, Write)

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
