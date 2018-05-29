/**
 * Created by Manjesh on 14-05-2016.
 */

var _ = require('lodash');
var mongodb = require('./mongodb');
var User = mongodb.User;
var OAuthClient = mongodb.OAuthClient;
var OAuthAccessToken = mongodb.OAuthAccessToken;
var OAuthAuthorizationCode = mongodb.OAuthAuthorizationCode;
var OAuthRefreshToken = mongodb.OAuthRefreshToken;


/* This method is called when a user is using a bearerToken they've already got as authentication
 i.e. when they're calling APIs. The method effectively serves to validate the bearerToken. A bearerToken
 has been successfully validated if passing it to the getUserIDFromBearerToken() method returns a userID.
 It's able to return a userID because each row in the access_tokens table has a userID in it so we can use
 the bearerToken to query for a row which will have a userID in it.
 The callback takes 2 parameters:
 1. A truthy boolean indicating whether or not an error has occured. It should be set to a truthy if
 there is an error or a falsy if there is no error
 2. An accessToken which contains an expiration date, you can assign null to ensure the token doesnin't expire.
 Then either a user object, or a userId which is a string or a number.
 If you create a user object you can access it in authenticated endpoints in the req.user object.
 If you create a userId you can access it in authenticated endpoints in the req.user.id object.
 */
function getAccessToken(bearerToken) {
  console.log("getAccessToken",bearerToken)
  return OAuthAccessToken
  //User,OAuthClient
    .findOne({access_token: bearerToken})
    .populate('User')
    .populate('OAuthClient')
    .then(function (accessToken) {
      console.log('at',accessToken)
      if (!accessToken) return false;
      var token = accessToken;
      token.user = token.User;
      token.client = token.OAuthClient;
      token.scope = token.scope
      return token;
    })
    .catch(function (err) {
      console.log("getAccessToken - Err: ")
    });
}





/* This method returns the client application which is attempting to get the accessToken.
 The client is normally be found using the  clientID & clientSecret. However, with user facing client applications such
 as mobile apps or websites which use the password grantType we don't use the clientID or clientSecret in the authentication flow.
 Therefore, although the client  object is required by the library all of the client's fields can be  be null. This also
 includes the grants field. Note that we did, however, specify that we're using the password grantType when we made the
 oAuth object in the index.js file.
 The callback takes 2 parameters. The first parameter is an error of type falsey and the second is a client object.
 As we're not of retrieving the client using the clientID and clientSecret (as we're using the password grantType)
 we can just create an empty client with all null values.Because the client is a hardcoded object
 - as opposed to a client we've retrieved through another operation - we just pass false for the error parameter
 as no errors can occur due to the aforemtioned hardcoding */
function getClient(clientId, clientSecret) {
  console.log("getClient",clientId, clientSecret)
  const options = {client_id: clientId};
  if (clientSecret) options.client_secret = clientSecret;

  return OAuthClient
    .findOne(options)
    .then(function (client) {
      if (!client) return new Error("client not found");
      var clientWithGrants = client
      clientWithGrants.grants = ['authorization_code', 'password', 'refresh_token', 'client_credentials']
      // Todo: need to create another table for redirect URIs
      clientWithGrants.redirectUris = [clientWithGrants.redirect_uri]
      delete clientWithGrants.redirect_uri
      //clientWithGrants.refreshTokenLifetime = integer optional
      //clientWithGrants.accessTokenLifetime  = integer optional
      return clientWithGrants
    }).catch(function (err) {
      console.log("getClient - Err: ", err)
    });
}




/* The method attempts to find a user with the spcecified username and password. The callback takes 2 parameters.
 This first parameter is an error of type truthy, and the second is a user object. You can decide the structure of
 the user object as you will be the one accessing the data in the user object in the saveAccessToken() method. The library
 doesn't access the user object it just supplies it to the saveAccessToken() method */
function getUser(username, password) {
  return User
    .findOne({username: username})
    .then(function (user) {
      console.log("u",user)
      return user.password === password ? user : false;
    })
    .catch(function (err) {
      console.log("getUser - Err: ", err)
    });
}

function revokeAuthorizationCode(code) {
  console.log("revokeAuthorizationCode",code)
  return OAuthAuthorizationCode.findOne({
    where: {
      authorization_code: code.code
    }
  }).then(function (rCode) {
    //if(rCode) rCode.destroy();
    /***
     * As per the discussion we need set older date
     * revokeToken will expected return a boolean in future version
     * https://github.com/oauthjs/node-oauth2-server/pull/274
     * https://github.com/oauthjs/node-oauth2-server/issues/290
     */
    var expiredCode = code
    expiredCode.expiresAt = new Date('2015-05-28T06:59:53.000Z')
    return expiredCode
  }).catch(function (err) {
    console.log("getUser - Err: ", err)
  });
}

function revokeToken(token) {
  console.log("revokeToken",token)
  return OAuthRefreshToken.findOne({
    where: {
      refresh_token: token.refreshToken
    }
  }).then(function (rT) {
    if (rT) rT.destroy();
    /***
     * As per the discussion we need set older date
     * revokeToken will expected return a boolean in future version
     * https://github.com/oauthjs/node-oauth2-server/pull/274
     * https://github.com/oauthjs/node-oauth2-server/issues/290
     */
    var expiredToken = token
    expiredToken.refreshTokenExpiresAt = new Date('2015-05-28T06:59:53.000Z')
    return expiredToken
  }).catch(function (err) {
    console.log("revokeToken - Err: ", err)
  });
}


function saveToken(token, client, user) {
  console.log("saveToken",token, client, user)
  return Promise.all([
      OAuthAccessToken.create({
        access_token: token.accessToken,
        expires: token.accessTokenExpiresAt,
        OAuthClient: client._id,
        User: user._id,
        scope: token.scope
      }),
      token.refreshToken ? OAuthRefreshToken.create({ // no refresh token for client_credentials
        refresh_token: token.refreshToken,
        expires: token.refreshTokenExpiresAt,
        OAuthClient: client._id,
        User: user._id,
        scope: token.scope
      }) : [],

    ])
    .then(function (resultsArray) {
      return _.assign(  // expected to return client and user, but not returning
        {
          client: client,
          user: user,
          access_token: token.accessToken, // proxy
          refresh_token: token.refreshToken, // proxy
        },
        token
      )
    })
    .catch(function (err) {
      console.log("revokeToken - Err: ", err)
    });
}

function getAuthorizationCode(code) {
  console.log("getAuthorizationCode",code)
  return OAuthAuthorizationCode
    .findOne({authorization_code: code})
    .populate('User')
    .populate('OAuthClient')
    .then(function (authCodeModel) {
      if (!authCodeModel) return false;
      var client = authCodeModel.OAuthClient
      var user = authCodeModel.User
      return reCode = {
        code: code,
        client: client,
        expiresAt: authCodeModel.expires,
        redirectUri: client.redirect_uri,
        user: user,
        scope: authCodeModel.scope,
      };
    }).catch(function (err) {
      console.log("getAuthorizationCode - Err: ", err)
    });
}

function saveAuthorizationCode(code, client, user) {
  console.log("saveAuthorizationCode",code, client, user)
  return OAuthAuthorizationCode
    .create({
      expires: code.expiresAt,
      OAuthClient: client._id,
      authorization_code: code.authorizationCode,
      User: user._id,
      scope: code.scope
    })
    .then(function () {
      code.code = code.authorizationCode
      return code
    }).catch(function (err) {
      console.log("saveAuthorizationCode - Err: ", err)
    });
}

function getUserFromClient(client) {
  console.log("getUserFromClient", client)
  var options = {client_id: client.client_id};
  if (client.client_secret) options.client_secret = client.client_secret;

  return OAuthClient
    .findOne(options)
    .populate('User')
    .then(function (client) {
      console.log(client)
      if (!client) return false;
      if (!client.User) return false;
      return client.User;
    }).catch(function (err) {
      console.log("getUserFromClient - Err: ", err)
    });
}

function getRefreshToken(refreshToken) {
  console.log("getRefreshToken", refreshToken)
  if (!refreshToken || refreshToken === 'undefined') return false
//[OAuthClient, User]
  return OAuthRefreshToken
    .findOne({refresh_token: refreshToken})
    .populate('User')
    .populate('OAuthClient')
    .then(function (savedRT) {
      console.log("srt",savedRT)
      var tokenTemp = {
        user: savedRT ? savedRT.User : {},
        client: savedRT ? savedRT.OAuthClient : {},
        refreshTokenExpiresAt: savedRT ? new Date(savedRT.expires) : null,
        refreshToken: refreshToken,
        refresh_token: refreshToken,
        scope: savedRT.scope
      };
      return tokenTemp;

    }).catch(function (err) {
      console.log("getRefreshToken - Err: ", err)
    });
}

function validateScope(token, client, scope) {
    console.log("validateScope", token, client, scope)
    return (user.scope === client.scope) ? scope : false
}

function verifyScope(token, scope) {
    console.log("verifyScope", token, scope)
    return token.scope === scope
}
module.exports = {
  //generateOAuthAccessToken, optional - used for jwt
  //generateAuthorizationCode, optional
  //generateOAuthRefreshToken, - optional
  getAccessToken: getAccessToken,
  getAuthorizationCode: getAuthorizationCode, //getOAuthAuthorizationCode renamed to,
  getClient: getClient,
  getRefreshToken: getRefreshToken,
  getUser: getUser,
  getUserFromClient: getUserFromClient,
  //grantTypeAllowed, Removed in oauth2-server 3.0
  revokeAuthorizationCode: revokeAuthorizationCode,
  revokeToken: revokeToken,
  saveToken: saveToken,//saveOAuthAccessToken, renamed to
  saveAuthorizationCode: saveAuthorizationCode, //renamed saveOAuthAuthorizationCode,
  //validateScope: validateScope,
  verifyScope: verifyScope,
}

