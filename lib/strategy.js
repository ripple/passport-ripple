/**
* Module dependencies.
*/
var util = require('util')
, OAuth2Strategy = require('passport-oauth2')
, InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
* `Strategy` constructor.
*
* The Ripple authentication strategy authenticates requests by delegating to
* Ripple ID using the OAuth 2.0 protocol.
*
* Applications must supply a `verify` callback which accepts an `accessToken`,
* `refreshToken` and service-specific `profile`, and then calls the `done`
* callback supplying a `user`, which should be set to `false` if the
* credentials are not valid.  If an exception occured, `err` should be set.
*
* Options:
*   - `clientID`      your Ripple ID application's Client ID
*   - `clientSecret`  your Ripple ID application's Client Secret
*   - `callbackURL`   URL to which Ripple ID will redirect the user after granting authorization
*   - `scope`         array of permission scopes to request.  valid scopes include:
*                     'user', 'funds' or none.
*   — `userAgent`     All API requests MUST include a valid User Agent string.
*                     e.g: domain name of your application.
*
* Examples:
*
*     passport.use(new RippleStrategy({
*         clientID: '123-456-789',
*         clientSecret: 'shhh-its-a-secret'
*         callbackURL: 'https://www.example.net/auth/ripple/callback',
*         userAgent: 'myapp.com'
*       },
*       function(accessToken, refreshToken, profile, done) {
*         User.findOrCreate(..., function (err, user) {
*           done(err, user);
*         });
*       }
*     ));
*
* @param {Object} options
* @param {Function} verify
* @api public
*/
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://id.ripple.com/dialog/authorize';
  options.tokenURL = options.tokenURL || 'https://id.ripple.com/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-ripple';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'ripple';
  //this._oauth2.setAccessTokenName("oauth_token");

  this._userProfileURL = options.userProfileURL || 'https://id.ripple.com/api/identity/profile';
}

/**
* Inherit from `OAuth2Strategy`.
*/
util.inherits(Strategy, OAuth2Strategy);


/**
* Retrieve user profile from Ripple ID.
*
* This function constructs a normalized profile, with the following properties:
*
*   - `provider`         always set to `Ripple`
*   - `identity`         the user's Ripple name
*
* @param {String} accessToken
* @param {Function} done
* @api protected
*/
Strategy.prototype.userProfile = function(accessToken, done) {

  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      var json = JSON.parse(body);
      json.provider = 'Ripple';
      done(null, json);
    } catch (e) {
      done(e);
    }
  });
};

/**
* Return extra parameters to be included in the authorization request.
*
* Some OAuth 2.0 providers allow additional, non-standard parameters to be
* included when requesting authorization.  Since these parameters are not
* standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
* strategies can overrride this function in order to populate these parameters
* as required by the provider.
*
* @param {Object} options
* @return {Object}
* @api protected
*/
// options include:
//   _type: tells Identity Service new user should be registered.
//   _cip_done: tells Identity Service this user has completed
//              Customer Identification Process with the caller.
// app.get('/auth/ripple/login',    passport.authenticate('ripple'));
// app.get('/auth/ripple/register', passport.authenticate('ripple', {_type: "signup"}));
Strategy.prototype.authorizationParams = function(options) {
  var response = {};
  if (options._type === "signup") response._login = "register";
  if (options._cip_done) response._cip_done = options._cip_done;
  return response;
};

/**
* Expose `Strategy`.
*/
module.exports = Strategy;
