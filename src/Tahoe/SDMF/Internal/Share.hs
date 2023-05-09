-- | Deal with details related to the structural layout of an SDMF share.
module Tahoe.SDMF.Internal.Share where

import Crypto.Cipher.AES (AES128)
import Crypto.Types (IV)
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word64, Word8)
import Tahoe.CHK.Merkle (MerkleTree)

{- | Structured representation of a single version SDMF share.

 See Tahoe-LAFS "mutable" specification document, section title "SDMF Slot
 Format".

 Since the only version of SDMF that is specified uses version 0, this
 implicitly represents a version 0 SDMF.  If new versions of SDMF are
 specified then new constructors may be added.
-}
data Share = Share
    { -- | sequence number. 2^64-1 must be handled specially, TBD
      shareSequenceNumber :: Word64
    , -- | "R" (root of share hash merkle tree)
      shareRootHash :: B.ByteString
    , -- | The IV for encryption of share data.
      shareIV :: IV AES128
    , -- | The total number of encoded shares (k).
      shareTotalShares :: Word8
    , -- | The number of shares required for decoding (N).
      shareRequiredShares :: Word8
    , -- | The size of a single ciphertext segment.
      shareSegmentSize :: Word64
    , -- | The length of the original plaintext.
      shareDataLength :: Word64
    , -- | The 2048 bit "verification" RSA key.
      shareVerificationKey :: RSA.PublicKey
    , -- | The RSA signature of
      -- H('\x00'+shareSequenceNumber+shareRootHash+shareIV+encoding
      -- parameters) where '\x00' gives the version of this share format (0)
      -- and the encoding parameters are a certain serialization of
      -- shareRequiredShares and shareTotalShares.
      shareSignature :: B.ByteString
    , -- | The share numbers and shareRootHash values which are required to
      -- ... something about verification I dunno. XXX
      shareHashChain :: [(Word8, B.ByteString)]
    , -- | A merkle tree where leaves are the hashes of the blocks in this share.
      shareBlockHashTree :: MerkleTree
    , -- | The share data (erasure encoded ciphertext).
      shareData :: LB.ByteString
    , -- | The encrypted 2048 bit "signature" RSA key.
      shareEncryptedPrivateKey :: B.ByteString
    }
    deriving (Show)
