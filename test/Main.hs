module Main (main) where

import Hedgehog (
    Property,
    forAll,
    property,
    tripping,
 )

import qualified Data.Binary as Binary
import Generators (shares)
import System.IO (hSetEncoding, stderr, stdout, utf8)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.Hedgehog (testProperty)

tests :: TestTree
tests =
    testGroup
        "SSK"
        [ testProperty "round-trips through bytes" $
            property $ do
                let decode' = ((\(_, _, sh) -> sh) <$>) . Binary.decodeOrFail
                share <- forAll shares
                tripping share Binary.encode decode'
                pure ()
        ]

main :: IO ()
main = do
    -- Hedgehog writes some non-ASCII and the whole test process will die if
    -- it can't be encoded.  Increase the chances that all of the output can
    -- be encoded by forcing the use of UTF-8 (overriding the LANG-based
    -- choice normally made).
    hSetEncoding stdout utf8
    hSetEncoding stderr utf8
    defaultMain tests
