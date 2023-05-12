-- | Deal with details related to the structural layout of an SDMF share.
module Tahoe.SDMF.Internal.Share where

import Control.Monad (unless)
import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types (IV, makeIV)
import qualified Crypto.PubKey.RSA.Types as RSA
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Encoding (encodeASN1), decodeASN1')
import Data.ASN1.Types (ASN1Object (fromASN1, toASN1))
import Data.Binary (Binary (..), Get, getWord8)
import Data.Binary.Get (bytesRead, getByteString, getLazyByteString, getRemainingLazyByteString, getWord16be, getWord32be, getWord64be, isEmpty, isolate)
import Data.Binary.Put (putByteString, putLazyByteString, putWord16be, putWord32be, putWord64be, putWord8)
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import Data.Word (Word16, Word64, Word8)
import Data.X509 (PubKey (PubKeyRSA))
import Tahoe.CHK.Merkle (MerkleTree, leafHashes)
import Tahoe.SDMF.Internal.Keys (SDMF_IV (..))

hashSize :: Int
hashSize = 32

newtype HashChain = HashChain
    { hashChain :: [(Word16, B.ByteString)]
    }
    deriving newtype (Eq, Show)

instance Binary HashChain where
    put (HashChain []) = mempty
    put (HashChain ((n, h) : c)) = do
        putWord16be n
        putByteString h
        put (HashChain c)

    get = do
        empty <- isEmpty
        if empty
            then pure $ HashChain []
            else do
                n <- getWord16be
                h <- getByteString hashSize
                (HashChain c) <- get
                pure $ HashChain ((n, h) : c)

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
      shareIV :: SDMF_IV
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
      shareHashChain :: HashChain
    , -- | A merkle tree where leaves are the hashes of the blocks in this share.
      shareBlockHashTree :: MerkleTree
    , -- | The share data (erasure encoded ciphertext).
      shareData :: LB.ByteString
    , -- | The encrypted 2048 bit "signature" RSA key.
      shareEncryptedPrivateKey :: B.ByteString
    }
    deriving (Eq, Show)

instance Binary Share where
    put Share{..} = do
        putWord8 0
        putWord64be shareSequenceNumber
        putByteString shareRootHash
        putByteString . ByteArray.convert $ shareIV
        putWord8 shareTotalShares
        putWord8 shareRequiredShares
        putWord64be shareSegmentSize
        putWord64be shareDataLength
        putWord32be signatureOffset
        putWord32be hashChainOffset
        putWord32be blockHashTreeOffset
        putWord32be shareDataOffset
        putWord64be encryptedPrivateKeyOffset
        putWord64be eofOffset
        putByteString verificationKeyBytes
        putByteString shareSignature
        put shareHashChain
        put shareBlockHashTree
        putLazyByteString shareData
        putByteString shareEncryptedPrivateKey
      where
        verificationKeyBytes = LB.toStrict . encodeASN1 DER . flip toASN1 [] . PubKeyRSA $ shareVerificationKey
        blockHashTreeBytes = B.concat . leafHashes $ shareBlockHashTree

        -- TODO Compute these from all the putting.
        signatureOffset = fromIntegral $ 1 + 8 + hashSize + 16 + 18 + 32 + B.length verificationKeyBytes
        hashChainOffset = signatureOffset + fromIntegral (B.length shareSignature)
        blockHashTreeOffset = hashChainOffset + fromIntegral (length (hashChain shareHashChain) * (hashSize + 2))
        shareDataOffset = blockHashTreeOffset + fromIntegral (B.length blockHashTreeBytes)
        encryptedPrivateKeyOffset = fromIntegral shareDataOffset + fromIntegral (LB.length shareData)
        eofOffset = encryptedPrivateKeyOffset + fromIntegral (B.length shareEncryptedPrivateKey)

    get = do
        version <- getWord8
        unless (version == 0) (fail $ "Only version 0 is supported; got version " <> show version)
        shareSequenceNumber <- getWord64be
        shareRootHash <- getByteString 32
        ivBytes <- getByteString 16
        shareIV <-
            SDMF_IV <$> case makeIV ivBytes of
                Nothing -> fail "Could not decode IV"
                Just iv -> pure iv

        shareTotalShares <- getWord8
        shareRequiredShares <- getWord8
        shareSegmentSize <- getWord64be
        shareDataLength <- getWord64be
        signatureOffset <- getWord32be
        hashChainOffset <- getWord32be
        blockHashTreeOffset <- getWord32be
        shareDataOffset <- getWord32be
        encryptedPrivateKeyOffset <- getWord64be
        eofOffset <- getWord64be

        pos <- bytesRead
        shareVerificationKey <- isolate (fromIntegral signatureOffset - fromIntegral pos) getSubjectPublicKeyInfo

        pos <- bytesRead
        shareSignature <- getByteString (fromIntegral hashChainOffset - fromIntegral pos)

        pos <- bytesRead
        shareHashChain <- isolate (fromIntegral blockHashTreeOffset - fromIntegral pos) get

        pos <- bytesRead
        shareBlockHashTree <- isolate (fromIntegral shareDataOffset - fromIntegral pos) get

        pos <- bytesRead
        shareData <- getLazyByteString (fromIntegral encryptedPrivateKeyOffset - fromIntegral pos)

        pos <- bytesRead
        shareEncryptedPrivateKey <- getByteString (fromIntegral eofOffset - fromIntegral pos)

        empty <- isEmpty
        unless empty (fail "Expected end of input but there are more bytes")

        pure Share{..}

{- | Read an X.509v3-encoded SubjectPublicKeyInfo structure carrying an ASN.1
 DER encoded RSA public key.
-}
getSubjectPublicKeyInfo :: Get RSA.PublicKey
getSubjectPublicKeyInfo = do
    verificationKeyBytes <- getRemainingLazyByteString
    let (Right asn1s) = decodeASN1' DER . LB.toStrict $ verificationKeyBytes
    let (Right (PubKeyRSA pubKey, [])) = fromASN1 asn1s
    pure pubKey
