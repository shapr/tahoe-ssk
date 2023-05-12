-- | Key types, derivations, and related functionality for SDMF.
module Tahoe.SDMF.Internal.Keys where

import Prelude hiding (Read)

import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types (Cipher (cipherInit, cipherKeySize), IV, KeySizeSpecifier (KeySizeFixed))
import Crypto.Error (maybeCryptoError)
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Random (MonadRandom)
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Encoding (encodeASN1))
import Data.ASN1.Types (ASN1Object (toASN1))
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as B
import Data.ByteString.Base32 (encodeBase32Unpadded)
import qualified Data.ByteString.Lazy as LB
import qualified Data.Text as T
import Data.X509 (PrivKey (PrivKeyRSA), PubKey (PubKeyRSA))
import Tahoe.CHK.Crypto (taggedHash, taggedPairHash)
import Tahoe.CHK.Server (StorageServerID)

newtype KeyPair = KeyPair {toPrivateKey :: RSA.PrivateKey}

toPublicKey :: KeyPair -> RSA.PublicKey
toPublicKey = RSA.private_pub . toPrivateKey

newtype Verification = Verification {unVerification :: RSA.PublicKey}
newtype Signature = Signature {unSignature :: RSA.PrivateKey}
data Write = Write {unWrite :: AES128, writeKeyBytes :: ByteArray.ScrubbedBytes}
data Read = Read {unRead :: AES128, readKeyBytes :: ByteArray.ScrubbedBytes}
newtype StorageIndex = StorageIndex {unStorageIndex :: B.ByteString}

newtype WriteEnablerMaster = WriteEnablerMaster B.ByteString
data WriteEnabler = WriteEnabler StorageServerID B.ByteString

data Data = Data {unData :: AES128, dataKeyBytes :: ByteArray.ScrubbedBytes}

newtype SDMF_IV = SDMF_IV (IV AES128)
    deriving (Eq)
    deriving newtype (ByteArray.ByteArrayAccess)

instance Show SDMF_IV where
    show (SDMF_IV iv) = T.unpack . T.toLower . encodeBase32Unpadded . ByteArray.convert $ iv

-- | The size of the public/private key pair to generate.
keyPairBits :: Int
keyPairBits = 2048

keyLength :: Int
(KeySizeFixed keyLength) = cipherKeySize (undefined :: AES128)

{- | Create a new, random key pair (public/private aka verification/signature)
 of the appropriate type and size for SDMF encryption.
-}
newKeyPair :: MonadRandom m => m KeyPair
newKeyPair = do
    (_, priv) <- RSA.generate keyPairBits e
    pure $ KeyPair priv
  where
    e = 0x10001

-- | Compute the write key for a given signature key for an SDMF share.
deriveWriteKey :: Signature -> Maybe Write
deriveWriteKey s =
    Write <$> key <*> pure (ByteArray.convert sbs)
  where
    sbs = taggedHash keyLength mutableWriteKeyTag . signatureKeyToBytes $ s
    key = maybeCryptoError . cipherInit $ sbs

mutableWriteKeyTag :: B.ByteString
mutableWriteKeyTag = "allmydata_mutable_privkey_to_writekey_v1"

-- | Compute the read key for a given write key for an SDMF share.
deriveReadKey :: Write -> Maybe Read
deriveReadKey w =
    Read <$> key <*> pure sbs
  where
    sbs = writeKeyBytes w
    key = maybeCryptoError . cipherInit . taggedHash keyLength mutableReadKeyTag . ByteArray.convert $ sbs

mutableReadKeyTag :: B.ByteString
mutableReadKeyTag = "allmydata_mutable_writekey_to_readkey_v1"

-- | Compute the data encryption/decryption key for a given read key for an SDMF share.
deriveDataKey :: SDMF_IV -> Read -> Maybe Data
deriveDataKey (SDMF_IV iv) r =
    Data <$> key <*> pure sbs
  where
    sbs = readKeyBytes r
    key = maybeCryptoError . cipherInit . taggedPairHash keyLength mutableDataKeyTag (B.pack . ByteArray.unpack $ iv) . ByteArray.convert $ sbs

mutableDataKeyTag :: B.ByteString
mutableDataKeyTag = "allmydata_mutable_readkey_to_datakey_v1"

mutableStorageIndexTag :: B.ByteString
mutableStorageIndexTag = "allmydata_mutable_readkey_to_storage_index_v1"

{- | Encode a public key to the Tahoe-LAFS canonical bytes representation -
 X.509 SubjectPublicKeyInfo of the ASN.1 DER serialization of an RSA
 PublicKey.
-}
verificationKeyToBytes :: Verification -> B.ByteString
verificationKeyToBytes = LB.toStrict . encodeASN1 DER . flip toASN1 [] . PubKeyRSA . unVerification

{- | Encode a private key to the Tahoe-LAFS canonical bytes representation -
 X.509 SubjectPublicKeyInfo of the ASN.1 DER serialization of an RSA
 PublicKey.
-}
signatureKeyToBytes :: Signature -> B.ByteString
signatureKeyToBytes = LB.toStrict . encodeASN1 DER . flip toASN1 [] . PrivKeyRSA . unSignature
