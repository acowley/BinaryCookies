{-# LANGUAGE OverloadedStrings #-}
-- | @binarycookies@ format documented at <http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/>
module Data.BinaryCookies (Cookie(..), Flags(..),
                           cookieText, cookies, cookiesFor,
                           cookieFile, parseCookies) where
import Control.Applicative ((<*), (<$>))
import Control.Monad (replicateM_, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except
import Data.Binary.Get
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import qualified Data.Foldable as F
import Data.Map (Map)
import qualified Data.Map as M
import Data.Monoid ((<>))
import qualified Data.Sequence as S
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Calendar
import Data.Time.Clock
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.Time.Format
import qualified Data.Vector as V
import System.Locale (defaultTimeLocale)
import Unsafe.Coerce (unsafeCoerce)

-- * Types

data CookieU = CookieU { _url        :: !Text
                       , _path       :: !Text
                       , _expiration :: !UTCTime
                       , _name       :: !Text
                       , _value      :: !Text
                       , _flags      :: !Flags }

data Cookie = Cookie { path       :: !Text
                     , expiration :: !UTCTime
                     , name       :: !Text
                     , value      :: !Text
                     , flags      :: !Flags }

data Flags = NoFlag | Secure | HttpOnly | SecureHttp deriving Show

instance Show Cookie where
  show (Cookie p e n v f) = 
    "(Cookie "++T.unpack p++" "++showTime e++" "++
    T.unpack n++": "++T.unpack v++" ("++show f++")"
    where showTime = formatTime defaultTimeLocale "%F"

-- * @cookies.txt@ Formatting

-- | Format a 'Cookie' in the style of Netscape's @cookies.txt@ file.
cookieText :: Text -> Cookie -> Text
cookieText d (Cookie p e n v f) = T.intercalate "\t"
                                                [d,"TRUE",p,s,e',n,v]
  where e' = T.pack . init $ show (utcTimeToPOSIXSeconds e)
        s = case f of
              Secure -> "TRUE"
              SecureHttp -> "TRUE"
              _ -> "FALSE"

-- | Format a @cookies.txt@ for a given domain.
cookies :: Text -> S.Seq Cookie -> Text
cookies d = T.intercalate "\n" . map (cookieText d) . F.toList

-- | Lookup and format all cookies for a given domain.
cookiesFor :: [Text] -> Map Text (S.Seq Cookie) -> Text
cookiesFor ds m = T.intercalate "\n" ("# Netscape HTTP Cookie File" : map go ds)
  where go d = maybe T.empty (cookies d) $ M.lookup d m

-- * Parsing

-- | Mac epoch/absolute time format starts from Jan 2001. Read the 8
-- bytes used to store this and convert to POSIX epoch.
macTime :: Get UTCTime
macTime = flip addUTCTime macEpoch . realToFrac <$> dblTime
  where macEpoch = UTCTime (fromGregorian 2001 1 1) 0
        dblTime = unsafeCoerce <$> getWord64le :: Get Double

-- | Gets a 32bit little-endian integer.
getInt :: ExceptT e Get Int
getInt = lift $ fmap fromIntegral getWord32le

getNulText :: ExceptT e Get Text
getNulText = lift $ T.decodeUtf8 . BL.toStrict <$> getLazyByteStringNul

accDomain :: Map Text (S.Seq Cookie) -> V.Vector CookieU
          -> Map Text (S.Seq Cookie)
accDomain = V.foldl' aux
  where aux m c = M.insertWith' (<>) (_url c) (S.singleton $ uc c) m
        uc (CookieU _ p e n v f) = Cookie p e n v f

cookieFlags :: ExceptT String Get Flags
cookieFlags = do flags' <- lift getWord32le
                 case () of
                   _ | flags' == 0 -> return NoFlag
                     | flags' == 1 -> return Secure
                     | flags' == 4 -> return HttpOnly
                     | flags' == 5 -> return SecureHttp
                     | otherwise -> throwE $ "Invalid cookie flag: "++show flags'

cookie :: ExceptT String Get CookieU
cookie = do _size <- getInt <* getInt
            flags' <- cookieFlags <* getInt
            _urlOffset <- getInt
            _nameOffset <- getInt
            _pathOffset <- getInt
            _valueOffset <- getInt
            eoc <- lift $ getWord64host
            unless (eoc == 0)
                   (throwE $ "Missing end-of-cookie: "++show eoc)
            expirationDate <- lift macTime
            _creationDate <- lift macTime
            url' <- getNulText
            name' <- getNulText
            path' <- getNulText
            value' <- getNulText
            return $ CookieU url' path' expirationDate name' value' flags'

page :: ExceptT String Get (V.Vector CookieU)
page = do sig <- lift getWord32be
          unless (sig == 0x00000100)
                 (throwE $ "Missing page signature: "++show sig)
          numCookies <- getInt
          -- offsets <- lift $ VU.replicateM numCookies getWord32le
          lift $ replicateM_ numCookies getWord32le
          endOfPage <- lift getWord32host
          unless (endOfPage == 0)           
                 (throwE $ "Missing end-of-page: "++show endOfPage)
          V.replicateM numCookies cookie

cookieFile :: ExceptT String Get (Map Text (S.Seq Cookie))
cookieFile = do sig <- lift $ getByteString 4
                unless (sig == BC.pack "cook")
                       (throwE "Missing header signature")
                numPages <- lift $ fmap fromIntegral getWord32be
                -- pageSizes <- lift $ VU.replicateM numPages getWord32be
                lift $ replicateM_ numPages getWord32host
                V.foldl' accDomain M.empty <$> V.replicateM numPages page

-- | Parse a @.binarycookies@ file, returning a 'Map' from domain to
-- 'Cookie'.
parseCookies :: FilePath -> IO (Either String (Map Text (S.Seq Cookie)))
parseCookies = fmap (runGet (runExceptT cookieFile)) . BL.readFile
