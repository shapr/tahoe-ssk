-- | Deal with details related to the structural layout of an SDMF share.
module Tahoe.SDMF.Internal.Share where

import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word32, Word64, Word8)
import Tahoe.CHK.Merkle (MerkleTree)

{- | Structured representation of a single version 0 SDMF share.

 See Tahoe-LAFS "mutable" specification document, section title "SDMF Slot
 Format".
-}
data Share = Share
    { shareSequenceNumber :: Word64
    , shareRootHash :: B.ByteString
    , shareIV :: B.ByteString
    , shareTotalShares :: Word8
    , shareRequiredShares :: Word8
    , shareSegmentSize :: Word64
    , shareDataLength :: Word8
    , shareOffsetSignature :: Word32
    , shareOffsetShareHashChain :: Word32
    , shareOffsetData :: Word32
    , shareOffsetEncryptedPrivateKey :: Word64
    , shareOffsetEOF :: Word64
    , shareVerificationKey :: RSA.PublicKey
    , shareSignature :: B.ByteString
    , shareHashChain :: [(Word8, B.ByteString)]
    , shareBlockHashTree :: MerkleTree
    , shareData :: LB.ByteString
    , sharePrivateKey :: RSA.PrivateKey
    }
