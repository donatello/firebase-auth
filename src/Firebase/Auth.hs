-- |
-- Module: Firebase.Auth
--
-- Types and functions to use Firebase Authentication.
module Firebase.Auth
    (
    -- * How to use this module
    -- $use

      Connector
    , mkConnector
    , runIO

    , SignupResponse(..)
    , signupWithEmailAndPassword

    , SigninResponse(..)
    , signinWithEmailAndPassword

    , RefreshIdResponse(..)
    , refreshIdToken

    , ProviderData(..)
    , UserData(..)
    , GetUserDataResponse(..)
    , getUserData

    , SendEmailVerificationResp(..)
    , sendEmailVerification

    , ConfirmEmailVerificationResp(..)
    , confirmEmailVerification

    , ApiErr(..)

    , extractTokenClaims

    , AuthError(..)
    ) where


import           Control.Error           (fmapL)
import           Crypto.JOSE.Compact     (decodeCompact)
import qualified Crypto.JOSE.JWK         as JWK
import qualified Crypto.JOSE.JWS         as JWS
import qualified Crypto.JOSE.Types       as JTypes
import qualified Crypto.JWT              as JWT
import           Crypto.PubKey.RSA.Types (PublicKey (..))
import           Data.Aeson.TH           (deriveJSON)
import qualified Data.ByteString.Base64  as B64
import qualified Data.ByteString.Char8   as B8
import qualified Data.HashMap.Strict     as H
import qualified Data.PEM                as Pem
import qualified Data.X509               as X509
import           Lens.Micro              ((&), (.~))
import qualified Network.HTTP.Types      as HT
import qualified UnliftIO.Concurrent     as Conc

import           Lib.Prelude

-- The Connector provides data required to make calls to the Firebase
-- endpoints.
data Connector = Connector
                 { cSecureTokenPubKeys :: Conc.MVar (H.HashMap Text JWT.JWK)
                 , cApiKey             :: ByteString
                 }

mkConnector :: (MonadIO m) => ByteString -> m Connector
mkConnector apiKey = do
    keyStore <- Conc.newMVar H.empty
    return $ Connector keyStore apiKey

-- The simplest way to call the Firebase APIs provided in this
-- module. Use this if your application does not already have a Monad
-- Transformer stack.
runIO :: Connector -> ReaderT Connector IO a -> IO a
runIO c m = flip runReaderT c m

setApiKey :: (MonadReader Connector m) => Request -> m Request
setApiKey r = do
    key <- asks cApiKey
    let q = getRequestQueryString r
    return $ setRequestQueryString (("key", Just key) : q) r

execRequest :: (ToJSON a, MonadReader Connector m, MonadIO m, FromJSON b)
            => [Char] -> a -> m (Either ApiErr b)
execRequest url body = do
    let iReq = parseRequest_ url
    req <- setApiKey $ setRequestBodyJSON body iReq
    resp <- httpBS req
    return $ parseResponse resp

-- A data type for errors when calling the Firebase APIs.
data ApiErr = AEJSONParseErr Text -- ^ A JSON parsing error - if this
                                  -- is returned, please report a bug.
            | AEApiErr Status Value -- ^ An error returned by the
                                    -- Firebase endpoint. The @Status@
                                    -- is the HTTP error code and the
                                    -- @Value@ is a raw JSON
                                    -- representation of the error
                                    -- details.
            deriving (Eq, Show)

parseResponse :: (FromJSON a) => Response ByteString -> Either ApiErr a
parseResponse resp =
    let st = getResponseStatus resp
        body = getResponseBody resp
    in
      if st == status200
      then either (Left . AEJSONParseErr . toS) Right $
           eitherDecodeStrict body
      else either (Left . AEJSONParseErr . toS) (Left . AEApiErr st) $
           eitherDecodeStrict body

data SignupResponse = SignupResponse { surKind         :: Text
                                     , surIdToken      :: Text
                                     , surEmail        :: Text
                                     , surRefreshToken :: Text
                                     , surExpiresIn    :: Text
                                     , surLocalId      :: Text
                                     }
                    deriving (Show, Eq)

$(deriveJSON (camelCase 3) ''SignupResponse)

signupWithEmailAndPassword :: (MonadReader Connector m, MonadIO m)
                           => Text -> Text
                           -> m (Either ApiErr SignupResponse)
signupWithEmailAndPassword email password = do
    let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser"
        body = object [ "email" .= email
                      , "password" .= password
                      , "returnSecureToken" .= True
                      ]
    execRequest url body

data SigninResponse = SigninResponse { sirKind         :: Text
                                     , sirIdToken      :: Text
                                     , sirEmail        :: Text
                                     , sirRefreshToken :: Text
                                     , sirExpiresIn    :: Text
                                     , sirLocalId      :: Text
                                     , sirRegistered   :: Bool
                                     }
                    deriving (Show, Eq)

$(deriveJSON (camelCase 3) ''SigninResponse)

signinWithEmailAndPassword :: (MonadReader Connector m, MonadIO m)
                           => Text -> Text
                           -> m (Either ApiErr SigninResponse)
signinWithEmailAndPassword email password = do
    let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword"
        body = object [ "email" .= email
                      , "password" .= password
                      , "returnSecureToken" .= True
                      ]
    execRequest url body

data RefreshIdResponse = RefreshIdResponse { rirExpiresIn    :: Text
                                           , rirTokenType    :: Text
                                           , rirRefreshToken :: Text
                                           , rirIdToken      :: Text
                                           , rirUserId       :: Text
                                           , rirProjectId    :: Text
                                           }
                       deriving (Eq, Show)

$(deriveJSON (dropCamelTo2 3) ''RefreshIdResponse)

refreshIdToken :: (MonadReader Connector m, MonadIO m)
               => Text -> m (Either ApiErr RefreshIdResponse)
refreshIdToken idToken = do
    let iReq = parseRequest_ "POST https://securetoken.googleapis.com/v1/token"
        body = [ ("grant_type", "refresh_token")
               , ("refresh_token", toS idToken)
               ]
    req <- setApiKey $ setRequestBodyURLEncoded body iReq
    resp <- httpBS req
    return $ parseResponse resp

data ProviderData = ProviderData { pdProviderId  :: Text
                                 , pdFederatedId :: Text
                                 }
                  deriving (Eq, Show)

$(deriveJSON (camelCase 2) ''ProviderData)

data UserData = UserData
                { udLocalId           :: Text
                , udEmail             :: Text
                , udEmailVerified     :: Bool
                , udDisplayName       :: Maybe Text
                , udProviderUserInfo  :: [ProviderData]
                , udPhotoUrl          :: Maybe Text
                , udPasswordHash      :: Maybe Text
                , udPasswordUpdatedAt :: Scientific -- epochMilliseconds
                , udValidSince        :: Text -- epochSeconds
                , udDisabled          :: Maybe Bool
                , udLastLoginAt       :: Maybe Text -- epochMilli
                , udCreatedAt         :: Text -- epochMilli
                , udCustomAuth        :: Maybe Bool
                }
              deriving (Eq, Show)

$(deriveJSON (camelCase 2) ''UserData)

data GetUserDataResponse = GetUserDataResponse { gudpKind  :: Text
                                               , gudpUsers :: [UserData]
                                               }
                         deriving (Eq, Show)

$(deriveJSON (camelCase 4) ''GetUserDataResponse)

getUserData :: (MonadReader Connector m, MonadIO m)
            => Text -> m (Either ApiErr GetUserDataResponse)
getUserData idToken = do
    let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo"
        body = object [ "idToken" .= idToken ]
    execRequest url body

data SendEmailVerificationResp = SendEmailVerificationResp { sevrKind  :: Text
                                                           , sevrEmail :: Text
                                                           }
                               deriving (Eq, Show)

$(deriveJSON (camelCase 4) ''SendEmailVerificationResp)

sendEmailVerification :: (MonadReader Connector m, MonadIO m)
                      => Text -> m (Either ApiErr SendEmailVerificationResp)
sendEmailVerification idToken = do
    let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode"
        body = object [ "requestType" .= ("VERIFY_EMAIL" :: Text)
                      , "idToken" .= idToken
                      ]
    execRequest url body

data ConfirmEmailVerificationResp = ConfirmEmailVerificationResp
                                    { cevrKind             :: Text
                                    , cevrLocalId          :: Maybe Text
                                    , cevrEmail            :: Text
                                    , cevrDisplayName      :: Maybe Text
                                    , cevrPhotoUrl         :: Maybe Text
                                    , cevrPasswordHash     :: Maybe Text
                                    , cevrProviderUserInfo :: [ProviderData]
                                    , cevrEmailVerified    :: Bool
                                    } deriving (Eq, Show)

$(deriveJSON (camelCase 4) ''ConfirmEmailVerificationResp)

confirmEmailVerification :: (MonadReader Connector m, MonadIO m)
                         => Text
                         -> m (Either ApiErr ConfirmEmailVerificationResp)
confirmEmailVerification oobCode = do
    let url = "POST https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo"
        body = object [ "oobCode" .= oobCode ]
    execRequest url body

-- $use
--
-- If your application already contains an Monad Transformer stack
-- (and it is an instance of MonadIO and MonadReader -- this is quite
-- common), then just add the Firebase.Auth.Connector to your reader
-- environment, and use Control.Monad.Reader.withReader to modify the
-- environment when calling functions in this module.
--
-- The simplest usage is in the `ReaderT Connector IO a` monad, as
-- used by the @runIO@ function. Just provide the Firebase API Key:
--
-- > result <- runIO "myAPIKeyxxx..." $
-- >           signupWithEmailAndPassword "user@example.com" "secret"
-- > case result of
-- >     Right signupResp -> print signupResp
-- >     Left apiErr -> print $ "Error: " ++ show apiErr

data AuthError = AEPublicKeyFetchHTTPStatus HT.Status
               | AECertParseError Text
               | AEUnexpectedCertFormat
               | AEInvalidToken
               | AEInvalidTokenHeader Text
               | AEUnknownKid
               | AETokenDecode Text
               | AEVerification Text
               | AEPayloadDecode Text
               | AEUnknown Text
               deriving (Eq, Show)

instance Exception AuthError

loadSecureTokenSigningKeys :: (MonadIO m)
                           => m (Either AuthError (H.HashMap Text JWT.JWK))
loadSecureTokenSigningKeys = do
    let url = "GET https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        req = parseRequest_ url
    resp <- httpJSONEither req
    let st = getResponseStatus resp
    if st == status200
        then return $ parseKeys $ fmapL (AECertParseError . show) $
             getResponseBody resp
        else return $ Left $ AEPublicKeyFetchHTTPStatus st

  where
    fromCertRaw :: ByteString -> Either AuthError X509.Certificate
    fromCertRaw s = do
        pems <- fmapL (AECertParseError . toS) $ Pem.pemParseBS s
        pem <- note (AECertParseError "No pem found") $ headMay pems
        signedExactCert <- fmapL (AECertParseError . toS) $
                           X509.decodeSignedCertificate $
                           Pem.pemContent pem
        let sCert = X509.getSigned signedExactCert
            cert = X509.signedObject sCert
        return cert

    getRSAKey (X509.PubKeyRSA (PublicKey size n e)) = Just (size, n, e)
    getRSAKey _                                     = Nothing

    certToJwk :: X509.Certificate -> Either AuthError JWT.JWK
    certToJwk cert = do
        (size, n, e) <- note AEUnexpectedCertFormat $ getRSAKey $
                        X509.certPubKey cert
        let jwk = JWK.fromKeyMaterial $ JWK.RSAKeyMaterial $
                  JWK.RSAKeyParameters (JTypes.SizedBase64Integer size n)
                  (JTypes.Base64Integer e) Nothing
            jwk' = jwk & JWK.jwkKeyOps .~ Just [JWK.Verify]
        return jwk'

    parseKeys :: Either AuthError (H.HashMap Text Text)
              -> Either AuthError (H.HashMap Text JWT.JWK)
    parseKeys b = do
        rawCertsMap <- H.map toS <$> b
        certsPairList <- forM (H.toList rawCertsMap) $ \(k, v) -> do
                             cert <- fromCertRaw v
                             return (k, cert)
        keyPairList <- forM certsPairList $ \(k, v) -> do
                           jwk <- certToJwk v
                           return (k, jwk)
        return $ H.fromList keyPairList

-- certRaw :: ByteString
-- certRaw = "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIWbdIODxWwn4wDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTgw\nNjEwMjEyMDEzWhcNMTgwNjI3MDkzNTEzWjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBALk4bcd+YUx4/E5Mnwl/2Fdcsf4A2vF75FAYyxD8fskpvADP\n7D+5JKI5nh4vUoS1Ix32PZD0QTThcv82aCXZHFSu6LSddcosG7QmnLKktWRt+2SP\nX/QCdM9XbtXK1xynB5rRzCGrPwC2SjH8cs+OJtu229ahfeiwpszBDhmfjNO+Y7It\nvBkCuKOhjGm9w4vxZeJyZRRj2tBKeV1M/B9FD3j/QuxmNuSLdMEuhJ4bgz/Lq5s1\nlBOEFnNvDd0Q4sqMu3Y4D8zdg5I/e94HPaJ28cRG7yCfi+MXnCxOp1g+CaJTMoMJ\niAvuR6UwAPpCTcIar5EIBFrRaswIDAx5812k5QECAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBACWQqzw/w4bch+fG2rjGCduecNYr5rLxzHo3Kj7W8s7e\nnkQznlUS/2X56DvvtKG/4gJiPSwfjGw+L2p9/FiDyAyZNAePXYpNgXVi/0APZahZ\ncOmiZMWeQWzNr6GSoWHGvWawXNOruCUioCF7g1Ryk78Rhd1lDuTXOtQiCgj55K1B\nqTASch4uau5ni+Zjjebu0njeleDK59NKmq5LUv0pRfrM3ifZr1rH2p8KoRO82cn9\n77GDrPQsO5yT5Uoe+pubeb/cMCq6Hngi0THK0P4XJDkojGYd0EgkDemdMg3GIXny\ngSgOb+W6c4VqRRUvK2o2BlIfGCitmFItmoSTrINNQNM=\n-----END CERTIFICATE-----\n"

-- idToken :: ByteString
-- idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdhM2QxOTA0ZjE4ZTI1Nzk0ODgzMWVhYjgwM2UxMmI3OTcxZTEzYWIifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbXlkZW1vLWI0MzVmIiwiYXVkIjoibXlkZW1vLWI0MzVmIiwiYXV0aF90aW1lIjoxNTI4NzQ5OTMxLCJ1c2VyX2lkIjoiVUNMeW9PcE9uaVZaYndhcUdKdDduMjdtQmhuMiIsInN1YiI6IlVDTHlvT3BPbmlWWmJ3YXFHSnQ3bjI3bUJobjIiLCJpYXQiOjE1Mjg3NDk5MzEsImV4cCI6MTUyODc1MzUzMSwiZW1haWwiOiJhZGl0eWFAbWluaW8uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJhZGl0eWFAbWluaW8uaW8iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.Zp3V4t86KJdtE4bciHmSAOb8AWMPJhSwb-hP-UTLoKpW8soVufnXlvOvxlOF5ptsyP9r0ScCaA8gGA6Og6RGqsXg3Q_eyqdGnGOeB2K0MLN4Kgk-YBHaUe4U6rUcXaN_kG3gdiLu7oIpzY8Afgyojj0H3r_4GQ_T7npVC-cf4XxjsvmICYh_i2UTc0TAgHsnWJKiHC49Ja-U53RARzLq2hkAAomWy_Bpy0Y_uDyHpsDdEg8wsdK400CZh-8ONklcaOCyAZaUFC63xUqJw1dvzA1975_h0V_gGneuAqldS0o7q0lovcl0KHRDkjiKNtr2g46l8ztNhuFrj5Dk4U_JrQ1"

-- Takes a token, parses header info and returns a pair of (algo, kid)
getTokenInfo :: ByteString -> Either AuthError (Text, Text)
getTokenInfo token = do
    header <- note AEInvalidToken $ headMay $ B8.split '.' token
    v <- fmapL (AEInvalidTokenHeader . show) $ eitherDecodeStrict $
         B64.decodeLenient header
    let [alg, kid] = ["alg", "kid"] :: [Text]
    note (AEInvalidTokenHeader "Missing alg or kid")
        ((,) <$> H.lookup alg v <*> H.lookup kid v)

verifyToken :: ByteString -> H.HashMap Text JWT.JWK
            -> IO (Either AuthError Value)
verifyToken token keyStore = do
    let resE = do
            (_, kid) <- getTokenInfo token
            jwk <- note AEUnknownKid $ H.lookup kid keyStore
            jws <- fmapL (AETokenDecode . show) $ (decodeCompact (toS token) :: Either JWT.Error JWT.SignedJWT)
            return (jwk, jws)
    case resE of
      Left err -> return $ Left err
      Right (jwk, jws) -> runExceptT $ do
          claims <- fmapLT (AEVerification . (show :: JWT.JWTError -> Text)) $
                    JWT.verifyClaims (JWT.defaultJWTValidationSettings (const True)) jwk jws
                    -- ExceptT $ (JWT.verifyClaims JWT.defaultJWTValidationSettings jwk jws -- :: IO (Either JWT.Error JWT.ClaimsSet))
          return $ toJSON claims

verifyTokenWithKeyReload :: (MonadIO m)
                         => ByteString -> H.HashMap Text JWT.JWK
                         -> Bool
                         -> m (Either AuthError (H.HashMap Text JWT.JWK, Value))
verifyTokenWithKeyReload token keyStore isReloaded =
    case getTokenInfo token of
        Left err -> return $ Left err
        Right (_, kid)
            | H.member kid keyStore -> runExceptT $ do
                  payload <- ExceptT $ liftIO $ verifyToken token keyStore
                  return (keyStore, payload)
            | isReloaded -> return $ Left AEUnknownKid
            | otherwise -> do
                  newStoreE <- loadSecureTokenSigningKeys
                  either
                      (return . Left)
                      (\store -> verifyTokenWithKeyReload token store True)
                      newStoreE

extractTokenClaims :: (MonadReader Connector m, MonadIO m, MonadUnliftIO m)
                   => ByteString -> m (Either AuthError Value)
extractTokenClaims token = do
    keyStoreVar <- asks cSecureTokenPubKeys
    Conc.modifyMVar keyStoreVar $ \keyStore -> do
        res <- verifyTokenWithKeyReload token keyStore False
        case res of
            Left err              -> return (keyStore, Left err)
            Right (newStore, val) -> return (newStore, Right val)
