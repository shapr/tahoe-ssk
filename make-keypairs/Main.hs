module Main where

import Codec.Crypto.RSA (generateKeyPair)
import Crypto.Random (CryptoRandomGen (newGenIO), SystemRandom)
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Encoding (encodeASN1))
import Data.ASN1.Types (ASN1Object (toASN1))
import qualified Data.ByteString.Lazy as LB

-- | The size of the keys to generate.
bits :: Int
bits = 2048

-- | The number of keys to generate.
count :: Int
count = 5

main :: IO ()
main = do
    g <- newGenIO :: IO SystemRandom
    mapM_ (genKey g) [0 .. count - 1]

genKey :: (Show a, CryptoRandomGen c) => c -> a -> IO ()
genKey g n =
    let (_, priv, _) = generateKeyPair g bits
        bytes = encodeASN1 DER (toASN1 priv [])
     in LB.writeFile ("test/data/rsa-privkey-" <> show n <> ".der") bytes
