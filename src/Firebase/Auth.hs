-- |
-- Module: Firebase.Auth
--
-- Types and functions to use Firebase Authentication.
module Firebase.Auth
    (
    -- * How to use this module
    -- $use

      Connector
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
    ) where



import           Data.Aeson.TH (deriveJSON)
import           Data.String   (IsString (fromString))

import           Lib.Prelude

-- The Connector provides data required to make calls to the Firebase
-- endpoints. It is an instance of `IsString` instance that can be
-- used to provide the Firebase API Key.
data Connector = Connector { cApiKey :: ByteString
                           }
                 deriving (Show, Eq)

instance IsString Connector where
    fromString = Connector . toS

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
