module Generators where

import Crypto.Cipher.Types (makeIV)
import Crypto.Hash (HashAlgorithm (hashDigestSize))
import Crypto.Hash.Algorithms (SHA256 (SHA256))
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Decoding (decodeASN1), ASN1Encoding (encodeASN1))
import Data.ASN1.Types (ASN1Object (fromASN1, toASN1))
import Data.Bifunctor (Bifunctor (first))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import Data.X509 (PrivKey (PrivKeyRSA))
import GHC.IO.Unsafe (unsafePerformIO)
import Hedgehog (MonadGen)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Tahoe.CHK.Merkle (MerkleTree (..), makeTreePartial)
import Tahoe.SDMF (Share (..))
import Tahoe.SDMF.Internal.Share (HashChain (HashChain))
import qualified Tahoe.SDMF.Keys as Keys

rootHashLength :: Int
rootHashLength = 32

ivLength :: Int
ivLength = 16

signatureLength :: Range.Range Int
signatureLength = Range.linear 250 260

{- | Generate SDMF shares.  The contents of the share are not necessarily
 semantically valid.
-}
shares :: MonadGen m => m Share
shares = do
    keypair <- genRSAKeys
    iv <- makeIV <$> Gen.bytes (Range.singleton ivLength)
    case iv of
        Nothing -> error "Could not build IV for SDMF share"
        Just iv' ->
            Share
                <$> Gen.word64 Range.exponentialBounded -- shareSequenceNumber
                <*> Gen.bytes (Range.singleton rootHashLength) -- shareRootHash
                <*> pure (Keys.SDMF_IV iv') -- shareIV
                <*> Gen.word8 Range.exponentialBounded -- shareTotalShares
                <*> Gen.word8 Range.exponentialBounded -- shareRequiredShares
                <*> Gen.word64 Range.exponentialBounded -- shareSegmentSize
                <*> Gen.word64 Range.exponentialBounded -- shareDataLength
                <*> pure (Keys.toPublicKey keypair) -- shareVerificationKey
                <*> Gen.bytes signatureLength -- shareSignature
                <*> shareHashChains -- shareHashChain
                <*> merkleTrees (Range.singleton 1) -- shareBlockHashTree
                <*> (LB.fromStrict <$> Gen.bytes (Range.exponential 0 1024)) -- shareData
                <*> (pure . LB.toStrict . toDER . PrivKeyRSA . Keys.toPrivateKey) keypair -- shareEncryptedPrivateKey
  where
    toDER = encodeASN1 DER . flip toASN1 []

{- | Build RSA key pairs.

 Because the specific bits of the key pair shouldn't make any difference to
 any application logic, generating new RSA key pairs is expensive, and
 generating new RSA key pairs in a way that makes sense in Hedgehog is
 challenging, this implementation just knows a few RSA key pairs already and
 will give back one of them.
-}
genRSAKeys :: MonadGen m => m Keys.KeyPair
genRSAKeys = Gen.element (map rsaKeyPair rsaKeyPairBytes)

-- I'm not sure how to do IO in MonadGen so do the IO up front unsafely (but
-- hopefully not really unsafely).
rsaKeyPairBytes :: [LB.ByteString]
{-# NOINLINE rsaKeyPairBytes #-}
rsaKeyPairBytes = unsafePerformIO $ mapM (\n -> LB.readFile ("test/data/rsa-privkey-" <> show n <> ".der")) [0 .. 4 :: Int]

rsaKeyPair :: LB.ByteString -> Keys.KeyPair
rsaKeyPair bs = do
    let (Right kp) = do
            asn1s <- first show (decodeASN1 DER bs)
            (r, _) <- fromASN1 asn1s
            case r of
                PrivKeyRSA pk -> pure $ Keys.KeyPair pk
                _ -> error "Expected RSA Private Key"
    kp

merkleTrees :: MonadGen m => Range.Range Int -> m MerkleTree
merkleTrees r = makeTreePartial <$> Gen.list r genHash

-- | Generate ByteStrings which could be sha256d digests.
genHash :: MonadGen m => m B.ByteString
genHash = Gen.bytes . Range.singleton . hashDigestSize $ SHA256

-- | Generate lists of two-tuples of share identifier and share root hash.
shareHashChains :: MonadGen m => m HashChain
shareHashChains = HashChain <$> Gen.list range element
  where
    range = Range.exponential 1 5
    element = (,) <$> Gen.integral (Range.exponential 0 255) <*> Gen.bytes (Range.singleton 32)
