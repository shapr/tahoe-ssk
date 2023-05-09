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
import Test.Tasty (TestTree, defaultMain, testGroup)
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
        ]
  where
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
