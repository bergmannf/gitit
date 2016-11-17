module Network.Gitit.Authentication.LDAP ( authUserLDAP ) where

import Network.Gitit.Types
import Network.Gitit.State

import Control.Monad (when)
import Control.Monad.Trans (liftIO)
import qualified Data.Map as M
import Text.Pandoc.Shared (substitute)
import Text.Printf (printf)
import System.Log.Logger(debugM, warningM)

import LDAP

ldapAuthQuery :: LDAP -> Maybe String -> String -> IO LDAPEntry
ldapAuthQuery ldapObj baseDN query =
  do
    let scope = LdapScopeSubtree
        attribs = LDAPAttrList ["id", "cn", "mail"]
    ldapSearch ldapObj baseDN scope (Just query) attribs False >>= return . head

{- | Quote any special characters part of search filters. -}
ldapQuote :: String -> String
ldapQuote = concatMap quoteChar
  where quoteChar c
          | c `elem` "*\\()\NUL/" = printf "\\%02x" c
          | otherwise  = [c]

authUserLDAP :: String -> String -> GititServerPart Bool
authUserLDAP name pass = do
  when (null pass) $ fail "LDAP password cannot be empty"

  cfg <- getConfig
  let host = ldapHost cfg
      port = LDAP.ldapPort -- FIXME
      baseDN = Just $ ldapBaseDN cfg
      filterExpr = case ldapFilter cfg of
        Just s -> s
        _ -> ""
      param = ldapQuote name
      query = substitute "%s" param filterExpr
  -- Establish an anonymous connection to allow querying for the user-dn
  ldap <- liftIO $ ldapInit host port
  user <- liftIO $ ldapAuthQuery ldap baseDN query

  let userDN = ledn user
      email = maybe "" head $ lookup "mail" $ leattrs user
      fullname = maybe "" head $ lookup "cn" $ leattrs user

  ok <- liftIO $ debugM "gitit" ("authenticating with DN " ++ userDN) >>
    (ldapSimpleBind ldap userDN pass >> return True) `catchLDAP`
      (\e -> warningM "gitit" ("authentication failure: " ++ show e)
             >> return False)

  when ok ((liftIO $ mkUser fullname email "")
           >>= (\user ->
                 updateGititState (\s ->
                                    s { users = M.insert name user (users s) })))

  -- u <- getUser name
  -- liftIO $ debugM "gitit" $ maybe "no valid user" show u
  return ok
