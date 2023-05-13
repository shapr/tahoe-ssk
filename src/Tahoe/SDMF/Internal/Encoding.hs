module Tahoe.SDMF.Internal.Encoding where

import Control.Monad.IO.Class (MonadIO (liftIO))
import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types (BlockCipher (blockSize), IV, makeIV)
import Crypto.Random (MonadRandom (getRandomBytes))
import Data.Bifunctor (Bifunctor (bimap))
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.Text as T
import Data.Word (Word16, Word64, Word8)
import Tahoe.CHK (padCiphertext, zfec, zunfec)
import Tahoe.CHK.Merkle (MerkleTree (MerkleLeaf))
import Tahoe.SDMF.Internal.Capability (Reader (..), Writer (..), deriveReader)
import qualified Tahoe.SDMF.Internal.Keys as Keys
import Tahoe.SDMF.Internal.Share (HashChain (HashChain), Share (..))

--- XXX Not sure why I have to nail down AES128 here
randomIV :: MonadRandom m => m (Maybe (IV AES128))
-- XXX Secure enough random source?
randomIV = (makeIV :: B.ByteString -> Maybe (IV AES128)) <$> getRandomBytes (blockSize (undefined :: AES128))

{- | Given a pre-determined key pair and sequence number, encode some
 ciphertext into a collection of SDMF shares.

 A key pair *unique identifies* a "slot" (the storage location for the shares).
 Thus they cannot be re-used for "different" data.  Any shares created with a
 given key pair are part of the same logical data object.
-}
encode :: (MonadFail m, MonadIO m, MonadRandom m) => Keys.KeyPair -> Word64 -> Word16 -> Word16 -> LB.ByteString -> m ([Share], Writer)
encode keypair shareSequenceNumber required total ciphertext = do
    blocks <- liftIO $ fmap LB.fromStrict <$> zfec (fromIntegral required) (fromIntegral total) (LB.toStrict $ padCiphertext required ciphertext)

    (Just iv) <- randomIV

    -- XXX fromIntegral is going from Word16 to Word8, not safe
    let makeShare' =
            flip $
                makeShare
                    shareSequenceNumber
                    (Keys.SDMF_IV iv)
                    (fromIntegral required)
                    (fromIntegral total)
                    (fromIntegral $ LB.length ciphertext)
                    (Keys.toVerificationKey keypair)

    let makeShare'' = makeShare' <$> blocks

        resultE :: Either T.Text [Share]
        resultE = (traverse . flip fmap) encryptedPrivateKey makeShare''
    either (fail . T.unpack) pure ((,) <$> resultE <*> cap)
  where
    -- We can compute a capability immediately.
    cap = capabilityForKeyPair keypair
    encryptedPrivateKey = flip Keys.encryptSignatureKey (Keys.toSignatureKey keypair) <$> (writerWriteKey <$> cap)

makeShare ::
    Word64 ->
    Keys.SDMF_IV ->
    Word8 ->
    Word8 ->
    Word64 ->
    Keys.Verification ->
    B.ByteString ->
    LB.ByteString ->
    Share
makeShare shareSequenceNumber shareIV shareRequiredShares shareTotalShares shareSegmentSize shareVerificationKey shareEncryptedPrivateKey shareData = Share{..}
  where
    shareRootHash = B.replicate 32 0
    shareDataLength = fromIntegral $ LB.length shareData -- XXX Partial
    shareSignature = B.replicate 32 0 -- XXX Actually compute sig, and is it 32 bytes?
    shareHashChain = HashChain []
    shareBlockHashTree = MerkleLeaf (B.replicate 32 0) -- XXX Real hash here, plus length check

decode :: (MonadFail m, MonadIO m) => Reader -> [(Word16, Share)] -> m LB.ByteString
decode _ [] = fail "Cannot decode with no shares"
decode _ s@((_, Share{shareRequiredShares, shareTotalShares, shareSegmentSize}) : shares)
    | length shares < fromIntegral shareRequiredShares = fail $ "got " <> show (length shares) <> " shares, required " <> show shareRequiredShares
    | otherwise = do
        ciphertext <- liftIO $ zunfec (fromIntegral shareRequiredShares) (fromIntegral shareTotalShares) (take (fromIntegral shareRequiredShares) blocks)
        pure . LB.take (fromIntegral shareSegmentSize) . LB.fromStrict $ ciphertext
  where
    blocks = bimap fromIntegral (LB.toStrict . shareData) <$> s

-- | Compute an SDMF write capability for a given keypair.
capabilityForKeyPair :: Keys.KeyPair -> Either T.Text Writer
capabilityForKeyPair keypair =
    Writer <$> writerWriteKey <*> maybeToEither' "Failed to derive read capability" writerReader
  where
    writerWriteKey = maybeToEither "Failed to derive write key" . Keys.deriveWriteKey . Keys.toSignatureKey $ keypair
    verificationKeyHash = Keys.deriveVerificationHash . Keys.toVerificationKey $ keypair
    writerReader = deriveReader <$> writerWriteKey <*> pure verificationKeyHash

maybeToEither :: a -> Maybe b -> Either a b
maybeToEither a Nothing = Left a
maybeToEither _ (Just b) = Right b

maybeToEither' :: e -> Either e (Maybe a) -> Either e a
maybeToEither' e (Right Nothing) = Left e
maybeToEither' _ (Right (Just r)) = Right r
maybeToEither' _ (Left e) = Left e
