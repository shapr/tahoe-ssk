{-# LANGUAGE TupleSections #-}

module Tahoe.SDMF.Internal.Encoding where

import Control.Monad.IO.Class (MonadIO (liftIO))
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word16, Word64, Word8)

import Crypto.Cipher.AES128 (AESKey128, BlockCipher (buildKey))
import Crypto.Classes (getIVIO)
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Types (IV)
import Data.Bifunctor (Bifunctor (bimap))
import qualified Data.ByteString as B
import Tahoe.CHK (padCiphertext, zfec, zunfec)
import Tahoe.CHK.Crypto (taggedHash)
import Tahoe.CHK.Encrypt (encrypt)
import Tahoe.CHK.Merkle (MerkleTree (MerkleLeaf))
import Tahoe.SDMF.Internal.Capability (Reader (..), Writer (..), deriveReader)
import Tahoe.SDMF.Internal.Share (HashChain (HashChain), Share (..), signatureKeyToBytes, verificationKeyToBytes)

{- | Given a pre-determined key pair and sequence number, encode some
 ciphertext into a collection of SDMF shares.

 A key pair *unique identifies* a "slot" (the storage location for the shares).
 Thus they cannot be re-used for "different" data.  Any shares created with a
 given key pair are part of the same logical data object.
-}
encode :: (MonadFail m, MonadIO m) => RSA.KeyPair -> Word64 -> Word16 -> Word16 -> LB.ByteString -> m ([Share], Writer)
encode keypair shareSequenceNumber required total ciphertext = do
    -- XXX Ciphertext needs to be padded to a multiple of required right?
    blocks <- liftIO $ zfec (fromIntegral required) (fromIntegral total) (LB.toStrict $ padCiphertext required ciphertext)

    -- XXX Secure enough random source?
    iv <- liftIO (getIVIO :: IO (IV AESKey128))

    -- XXX fromIntegral is going from Word16 to Word8, not safe
    makeShare' <- makeShare shareSequenceNumber iv (fromIntegral required) (fromIntegral total) (fromIntegral $ LB.length ciphertext) (RSA.toPublicKey keypair) <$> encryptedPrivateKey

    let shares = makeShare' . LB.fromStrict <$> blocks
    (shares,) <$> cap
  where
    -- We can compute a capability immediately.
    cap = capabilityForKeyPair keypair
    encryptedPrivateKey = flip encryptPrivateKey (RSA.toPrivateKey keypair) <$> (writerWriteKey <$> cap)

encryptPrivateKey :: AESKey128 -> RSA.PrivateKey -> B.ByteString
encryptPrivateKey key = LB.toStrict . encrypt key . LB.fromStrict . signatureKeyToBytes

makeShare ::
    Word64 ->
    IV AESKey128 ->
    Word8 ->
    Word8 ->
    Word64 ->
    RSA.PublicKey ->
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
capabilityForKeyPair :: MonadFail m => RSA.KeyPair -> m Writer
capabilityForKeyPair keypair =
    Writer <$> writerWriteKey <*> writerReader
  where
    writerWriteKey = deriveWriteKey . RSA.toPrivateKey $ keypair
    verificationKeyHash = hashVerificationKey . RSA.toPublicKey $ keypair
    writerReader = deriveReader <$> writerWriteKey <*> pure verificationKeyHash

-- | Compute the write key for a given signature key for an SDMF share.
deriveWriteKey :: MonadFail m => RSA.PrivateKey -> m AESKey128
deriveWriteKey privKey = do
    let key = buildKey . taggedHash writeKeyLength mutableWriteKeyTag . signatureKeyToBytes $ privKey
    case key of
        Nothing -> fail "Couldn't build AESKey128"
        Just k -> pure k

{- | The tag used when hashing the signature key to the write key for the
 creation of an SDMF capability.
-}
mutableWriteKeyTag :: B.ByteString
mutableWriteKeyTag = "allmydata_mutable_privkey_to_writekey_v1"

writeKeyLength :: Int
writeKeyLength = 16

{- | Compute the verification key hash of the given verification key for
 inclusion in an SDMF share.
-}
hashVerificationKey :: RSA.PublicKey -> B.ByteString
hashVerificationKey = taggedHash verificationKeyHashLength mutableVerificationKeyHashTag . verificationKeyToBytes

verificationKeyHashLength :: Int
verificationKeyHashLength = 32

{- | The tag used when hashing the verification key to the verification key
 hash for inclusion in SDMF shares.
-}
mutableVerificationKeyHashTag :: B.ByteString
mutableVerificationKeyHashTag = "allmydata_mutable_pubkey_to_fingerprint_v1"
