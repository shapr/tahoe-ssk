module Tahoe.SDMF.Internal.Encrypting where

import Crypto.Cipher.Types (ctrCombine, nullIV)
import qualified Data.ByteString.Lazy as LB
import qualified Tahoe.SDMF.Internal.Keys as Keys

encrypt :: Keys.Data -> LB.ByteString -> LB.ByteString
encrypt Keys.Data{unData} = LB.fromStrict . ctrCombine unData nullIV . LB.toStrict

decrypt :: Keys.Data -> LB.ByteString -> LB.ByteString
decrypt = encrypt
