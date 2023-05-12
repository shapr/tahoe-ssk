module Main where

import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Encoding (encodeASN1))
import Data.ASN1.Types (ASN1Object (toASN1))
import qualified Data.ByteString.Lazy as LB
import Data.X509 (PrivKey (PrivKeyRSA))

-- | The size of the keys to generate.
bits :: Int
bits = 2048

-- | The number of keys to generate.
count :: Int
count = 5

main :: IO ()
main = do
    mapM_ genKey [0 .. count - 1]

genKey :: Show a => a -> IO ()
genKey n = do
    (_, priv) <- RSA.generate bits e
    let bytes = encodeASN1 DER (toASN1 (PrivKeyRSA priv) [])
    LB.writeFile ("test/data/rsa-privkey-" <> show n <> ".der") bytes
  where
    e = 0x10001
