-- | Structured representations of SDMF capabilities.
module Tahoe.SDMF.Internal.Capability where

import Prelude hiding (Read)

import Control.Applicative ((<|>))
import Control.Monad (void)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.Binary (decode)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base32 as B
import qualified Data.ByteString.Lazy as LB
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Void (Void)
import Data.Word (Word16)
import Tahoe.SDMF.Internal.Keys (Read, StorageIndex (StorageIndex), Write, deriveReadKey, deriveStorageIndex)
import Text.Megaparsec (ErrorFancy (ErrorFail), Parsec, count, failure, fancyFailure, oneOf)
import Text.Megaparsec.Char (char, string)

data Verifier = Verifier
    { verifierStorageIndex :: StorageIndex
    , verifierVerificationKeyHash :: Digest SHA256
    }

-- | A read capability for an SDMF object.
data Reader = Reader
    { readerReadKey :: Read
    , readerVerifier :: Verifier
    }

-- | A write capability for an SDMF object.
data Writer = Writer
    { writerWriteKey :: Write
    , writerReader :: Reader
    }

-- | Diminish a write key to a read key and wrap it in a reader capability.
deriveReader :: Write -> Digest SHA256 -> Maybe Reader
deriveReader w fingerprint = Reader <$> readKey <*> verifier
  where
    readKey = deriveReadKey w
    verifier = flip deriveVerifier fingerprint <$> readKey

deriveVerifier :: Read -> Digest SHA256 -> Verifier
deriveVerifier readKey = Verifier storageIndex
  where
    storageIndex = deriveStorageIndex readKey

data SDMF = SDMFVerifier Verifier | SDMFReader Reader | SDMFWriter Writer

type Parser = Parsec Void T.Text

-- | A parser for any kind of SDMF capability type.
pCapability :: Parser SDMF
pCapability = (SDMFVerifier <$> pVerifier) <|> (SDMFReader <$> pReader) <|> (SDMFWriter <$> pWriter)

-- | A parser for an SDMF verifier capability.
pVerifier :: Parser Verifier
pVerifier = uncurry Verifier <$> pPieces "URI:SSK-Verifier:" StorageIndex

-- | A parser for an SDMF reader capability.
pReader :: Parser Reader
pReader = do
    (readKey, verificationKeyHash) <- pPieces "URI:SSK-RO:" (decode . LB.fromStrict)
    let verifier = deriveVerifier readKey verificationKeyHash
    pure $ Reader readKey verifier

-- | A parser for an SDMF writer capability.
pWriter :: Parser Writer
pWriter = do
    (writeKey, verificationKeyHash) <- pPieces "URI:SSK:" (decode . LB.fromStrict)
    let reader = deriveReader writeKey verificationKeyHash
    case Writer writeKey <$> reader of
        Nothing -> failure Nothing mempty
        Just writer -> pure writer

pPieces :: T.Text -> (B.ByteString -> a) -> Parser (a, Digest SHA256)
pPieces prefix convertSecret = do
    void $ string prefix
    secret <- convertSecret <$> pBase32 rfc3548Alphabet 128
    void $ char ':'
    digestBytes <- pBase32 rfc3548Alphabet 256
    case digestFromByteString digestBytes of
        Nothing -> failure Nothing mempty
        Just verificationKeyHash ->
            pure (secret, verificationKeyHash)

{- | A parser combinator for an arbitrary byte string of a fixed length,
 encoded using base32.

 TODO: Avoid duplicating this implementation here and in tahoe-chk.
-}
pBase32 ::
    -- | The alphabet to use.  For example, *rfc3548Alphabet*.
    [Char] ->
    -- | The number of bits in the encoded byte string.
    Word16 ->
    -- | A parser for the byte string.  Strings that are not valid base32 will
    -- be rejected.  Strings that are the wrong length are *not necessarily*
    -- currently rejected!  Please fix that, somebody.
    Parser B.ByteString
pBase32 alpha bits = do
    b32Text <- pBase32Text
    either (fancyFailure . Set.singleton . ErrorFail . T.unpack) pure (decodeBase32Text b32Text)
  where
    decodeBase32Text = B.decodeBase32Unpadded . T.encodeUtf8
    pBase32Text = T.snoc <$> stem <*> trailer

    -- Determine how many full characters to expect along with how many bits
    -- are left to expect encoded in the final character.
    (full, extra) = bits `divMod` 5

    -- Match the base32 characters that represent the full 5 bits
    -- possible.  fromIntegral is okay here because `full` is only a
    -- Word16 and will definitely fit safely into the Int count wants.
    stem :: Parser T.Text
    stem = T.pack <$> count (fromIntegral full) (oneOf alpha)

    -- Match the final character that represents fewer than 5 bits.
    trailer :: Parser Char
    trailer = oneOf $ trailingChars alpha extra

    -- XXX The real trailing character set is smaller than this.  This
    -- parser will let through invalid characters that result in giving us
    -- possibly too many bits.
    trailingChars :: [Char] -> Word16 -> [Char]
    trailingChars alpha' _ = alpha'

{- | The RFC3548 standard alphabet used by Gnutella, Content-Addressable Web,
 THEX, Bitzi, Web-Calculus...
-}
rfc3548Alphabet :: [Char]
rfc3548Alphabet = "abcdefghijklmnopqrstuvwxyz234567"
