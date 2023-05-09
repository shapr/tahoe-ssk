module Generators where

import Crypto.Hash (HashAlgorithm (hashDigestSize))
import Crypto.Hash.Algorithms (SHA256 (SHA256))
import Crypto.Types (IV (..))
import qualified Crypto.Types.PubKey.RSA as RSA
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Decoding (decodeASN1), ASN1Encoding (encodeASN1))
import Data.ASN1.Types (ASN1Object (fromASN1, toASN1))
import Data.Bifunctor (Bifunctor (first))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word8)
import GHC.IO.Unsafe (unsafePerformIO)
import Hedgehog (MonadGen)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Tahoe.CHK.Merkle (MerkleTree (..), makeTreePartial)
import Tahoe.SDMF (Share (..))

rootHashLength :: Int
rootHashLength = undefined

ivLength :: Int
ivLength = undefined

signatureLength :: Int
signatureLength = undefined

{- | Generate SDMF shares.  The contents of the share are not necessarily
 semantically valid.
-}
shares :: MonadGen m => m Share
shares =
    genRSAKeys >>= \keypair ->
        Share
            <$> Gen.word64 Range.exponentialBounded -- shareSequenceNumber
            <*> Gen.bytes (Range.singleton rootHashLength) -- shareRootHash
            <*> (IV <$> Gen.bytes (Range.singleton ivLength)) -- shareIV
            <*> Gen.word8 Range.exponentialBounded -- shareTotalShares
            <*> Gen.word8 Range.exponentialBounded -- shareRequiredShares
            <*> Gen.word64 Range.exponentialBounded -- shareSegmentSize
            <*> Gen.word64 Range.exponentialBounded -- shareDataLength
            <*> pure (RSA.toPublicKey keypair) -- shareVerificationKey
            <*> Gen.bytes (Range.singleton signatureLength) -- shareSignature
            <*> shareHashChains -- shareHashChain
            <*> merkleTrees (Range.singleton 1) -- shareBlockHashTree
            <*> (LB.fromStrict <$> Gen.bytes (Range.exponential 0 1024)) -- shareData
            <*> (pure . LB.toStrict . toDER . RSA.toPrivateKey) keypair -- sharePrivateKey
  where
    toDER = encodeASN1 DER . flip toASN1 []

{- | Build RSA key pairs.

 Because the specific bits of the key pair shouldn't make any difference to
 any application logic, generating new RSA key pairs is expensive, and
 generating new RSA key pairs in a way that makes sense in Hedgehog is
 challenging, this implementation just knows a few RSA key pairs already and
 will give back one of them.
-}
genRSAKeys :: MonadGen m => m RSA.KeyPair
genRSAKeys = Gen.element (map rsaKeyPair rsaKeyPairBytes)

-- I'm not sure how to do IO in MonadGen so do the IO up front unsafely (but
-- hopefully not really unsafely).
rsaKeyPairBytes :: [LB.ByteString]
{-# NOINLINE rsaKeyPairBytes #-}
rsaKeyPairBytes = unsafePerformIO $ mapM (\n -> LB.readFile ("test/data/rsa-privkey-" <> show n <> ".der")) [0 .. 4 :: Int]

rsaKeyPair :: LB.ByteString -> RSA.KeyPair
rsaKeyPair bs = do
    let (Right kp) = do
            asn1s <- first show (decodeASN1 DER bs)
            (r, _) <- fromASN1 asn1s
            pure r
    kp

merkleTrees :: MonadGen m => Range.Range Int -> m MerkleTree
merkleTrees r = makeTreePartial <$> Gen.list r genHash

-- | Generate ByteStrings which could be sha256d digests.
genHash :: MonadGen m => m B.ByteString
genHash = Gen.bytes . Range.singleton . hashDigestSize $ SHA256

-- | Generate lists of two-tuples of share identifier and share root hash.
shareHashChains :: MonadGen m => m [(Word8, B.ByteString)]
shareHashChains = Gen.list range element
  where
    range = Range.exponential 1 5
    element = (,) <$> Gen.integral (Range.exponential 1 255) <*> Gen.bytes (Range.singleton 32)
