module Tahoe.SDMF.Internal.Encrypting where

import Crypto.Cipher.Types (ctrCombine)
import qualified Data.ByteString.Lazy as LB
import qualified Tahoe.SDMF.Internal.Keys as Keys

encrypt :: Keys.Data -> Keys.SDMF_IV -> LB.ByteString -> LB.ByteString
encrypt Keys.Data{unData} (Keys.SDMF_IV iv) = LB.fromStrict . ctrCombine unData iv . LB.toStrict

decrypt :: Keys.Data -> Keys.SDMF_IV -> LB.ByteString -> LB.ByteString
decrypt = encrypt
