-- | Implement the encryption scheme used by SDMF.
module Tahoe.SDMF.Internal.Encrypting where

import Crypto.Cipher.Types (ctrCombine, nullIV)
import qualified Data.ByteString.Lazy as LB
import qualified Tahoe.SDMF.Internal.Keys as Keys

{- | Encrypt plaintext bytes according to the scheme used for SDMF share
 construction.
-}
encrypt :: Keys.Data -> LB.ByteString -> LB.ByteString
encrypt Keys.Data{unData} = LB.fromStrict . ctrCombine unData nullIV . LB.toStrict

{- | Decrypt ciphertext bytes according to the scheme used for SDMF share
 construction.
-}
decrypt :: Keys.Data -> LB.ByteString -> LB.ByteString
decrypt = encrypt
