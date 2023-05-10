module Tahoe.SDMF.Internal.Encoding where

import Control.Monad.IO.Class (MonadIO)
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word16, Word64)

import qualified Crypto.PubKey.RSA.Types as RSA
import Tahoe.SDMF.Internal.Capability (Capability (..))
import Tahoe.SDMF.Internal.Share (Share)

{- | Given a pre-determined key pair and sequence number, encode some
 ciphertext into a collection of SDMF shares.

 A key pair *unique identifies* a "slot" (the storage location for the shares).
 Thus they cannot be re-used for "different" data.  Any shares created with a
 given key pair are part of the same logical data object.
-}
encode :: MonadIO m => RSA.KeyPair -> Word64 -> Word16 -> Word16 -> LB.ByteString -> m ([Share], Capability)
encode _keypair _seqNum _required _total _ciphertext = do
    pure ([], Capability)

decode :: MonadIO m => Capability -> [(Word16, Share)] -> m (Maybe LB.ByteString)
decode _cap _shares = pure Nothing
