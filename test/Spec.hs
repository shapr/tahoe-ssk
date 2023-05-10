module Spec where

import Hedgehog (
    forAll,
    property,
    tripping,
 )

import qualified Data.Binary as Binary
import Data.Binary.Get (ByteOffset)
import qualified Data.ByteString.Lazy as LB
import Generators (shareHashChains, shares)
import System.IO (hSetEncoding, stderr, stdout, utf8)
import Tahoe.SDMF (Share)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "SSK"
        [ testProperty "Hash chain round-trips through bytes" $
            property $ do
                hashChain <- forAll shareHashChains
                tripping hashChain Binary.encode decode'
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
