module Spec where

import Hedgehog (
    forAll,
    property,
    tripping,
 )

import Crypto.Cipher.Types (makeIV)
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1Object (fromASN1))
import qualified Data.Binary as Binary
import Data.Binary.Get (ByteOffset)
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as B
import Data.ByteString.Base32 (encodeBase32Unpadded)
import qualified Data.ByteString.Lazy as LB
import qualified Data.Text as T
import Data.X509 (PrivKey (PrivKeyRSA))
import Generators (shareHashChains, shares)
import System.IO (hSetEncoding, stderr, stdout, utf8)
import Tahoe.SDMF (Share)
import qualified Tahoe.SDMF.Keys as Keys
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)
import Test.Tasty.Hedgehog (testProperty)

-- The test suite compares against some hard-coded opaque strings.  These
-- expected values were determined using the expected_values.py program in
-- this directory.

tests :: TestTree
tests =
    testGroup
        "SSK"
        [ testProperty "Hash chain round-trips through bytes" $
            property $ do
                hashChain <- forAll shareHashChains
                tripping hashChain Binary.encode decode'
        , testCase "derived keys equal known-correct values" $
            -- The path is relative to the root of the package, which is where
            -- at least some test runners will run the test process.  If
            B.readFile "test/data/rsa-privkey-0.der" >>= \privBytes ->
                let (Just iv) = Keys.SDMF_IV <$> makeIV (B.replicate 16 0x42)
                    expectedWriteKey = ("ae6e6cgcllhty4z5l4dp5v7gee" :: T.Text)
                    expectedReadKey = ("rbx5xh5rztefvazy7sq32sw34y" :: T.Text)
                    expectedDataKey = ("4ay4y6itvk7cvynpyok3qmxf5y" :: T.Text)

                    (Right asn1s) = decodeASN1' DER privBytes
                    (Right (PrivKeyRSA privKey, [])) = fromASN1 asn1s
                    (Just w@(Keys.Write _ derivedWriteKey)) = Keys.deriveWriteKey (Keys.Signature privKey)
                    (Just r@(Keys.Read _ derivedReadKey)) = Keys.deriveReadKey w
                    (Just d@(Keys.Data _ derivedDataKey)) = Keys.deriveDataKey iv r

                    -- Format a key as text for convenient comparison to
                    -- expected value.
                    fmtKey = T.toLower . encodeBase32Unpadded . ByteArray.convert
                 in do
                        -- In general it might make more sense to convert expected
                        -- into ScrubbedBytes instead of converting derived into
                        -- ByteString but ScrubbedBytes doesn't have a useful Show
                        -- instance so we go the other way.  We're not worried about
                        -- the safety of these test-only keys anyway.
                        assertEqual
                            "expected writekey /= derived writekey"
                            expectedWriteKey
                            (fmtKey derivedWriteKey)
                        assertEqual
                            "expected readkey /= derived readkey"
                            expectedReadKey
                            (fmtKey derivedReadKey)
                        assertEqual
                            "expected datakey /= derived datakey"
                            expectedDataKey
                            (fmtKey derivedDataKey)
        , testProperty "Share round-trips through bytes" $
            property $ do
                share <- forAll shares
                tripping share Binary.encode decode'
        , testCase "known-correct serialized shares round-trip though Share" $
            mapM_ knownCorrectRoundTrip [0 :: Int .. 9]
        ]

{- | Load a known-correct SDMF bucket and assert that bytes in the slot it
 contains deserializes to a Share and then serializes back to the same bytes
-}
knownCorrectRoundTrip :: Show a => a -> IO ()
knownCorrectRoundTrip n = do
    -- The files are in "bucket" format.  We need to extract the
    -- "slot".  We do so by stripping a prefix and suffix.  To avoid
    -- having to parse the prefix, we assert that the suffix is a
    -- predictable size.
    bucket <- LB.readFile ("test/data/3of10." <> show n)
    let withoutPrefix = LB.drop (32 + 20 + 32 + 8 + 8 + 368) bucket
        dataSize = LB.length withoutPrefix - 4
        shareData = LB.take dataSize withoutPrefix
        suffix = LB.drop dataSize withoutPrefix

    -- Our assumption about the data we're working on...
    assertEqual "Cannot account for extra leases" suffix "\0\0\0\0"

    let decoded = decode' shareData
    let encoded = (Binary.encode :: Share -> LB.ByteString) <$> decoded
    assertEqual "original /= encoded" (Right shareData) encoded

-- | Like `Binary.Binary.decodeOrFail` but only return the decoded value.
decode' :: Binary.Binary b => LB.ByteString -> Either (LB.ByteString, ByteOffset, String) b
decode' = ((\(_, _, a) -> a) <$>) . Binary.decodeOrFail

main :: IO ()
main = do
    -- Hedgehog writes some non-ASCII and the whole test process will die if
    -- it can't be encoded.  Increase the chances that all of the output can
    -- be encoded by forcing the use of UTF-8 (overriding the LANG-based
    -- choice normally made).
    hSetEncoding stdout utf8
    hSetEncoding stderr utf8
    defaultMain tests
