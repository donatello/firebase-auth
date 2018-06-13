{-
Welcome to your custom Prelude
Export here everything that should always be in your library scope
For more info on what is exported by Protolude check:
https://github.com/sdiehl/protolude/blob/master/Symbols.md
-}
module Lib.Prelude
    ( module Exports

    , camelCase
    , dropCamelTo2
    ) where

import           Protolude           as Exports

import           Data.Aeson          as Exports (FromJSON, ToJSON, Value,
                                                 eitherDecodeStrict, object,
                                                 (.=))
import           Data.Scientific     as Exports (Scientific)
import           Network.HTTP.Simple as Exports (Request, Response,
                                                 getRequestQueryString,
                                                 getResponseBody,
                                                 getResponseStatus, httpBS,
                                                 httpJSONEither, parseRequest_,
                                                 setRequestBodyJSON,
                                                 setRequestBodyURLEncoded,
                                                 setRequestQueryString)
import           Network.HTTP.Types  as Exports (Status, status200)
import           UnliftIO            as Exports (MonadUnliftIO)

import qualified Data.Aeson          as A
import qualified Data.Char           as C

-- Drop prefix of given length and lowercase the first character
camelCase :: Int -> A.Options
camelCase n = A.defaultOptions
              { A.fieldLabelModifier = lowerIt . drop n
              , A.omitNothingFields = True
              }
  where
    lowerIt []     = []
    lowerIt (a:as) = C.toLower a : as

dropCamelTo2 :: Int -> A.Options
dropCamelTo2 n = A.defaultOptions
                 { A.fieldLabelModifier = A.camelTo2 '_' . drop n
                 , A.omitNothingFields = True
                 }
