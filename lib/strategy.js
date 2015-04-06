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

      var profile = { provider: 'Ripple' };
      profile.identity = json.identity;
      profile.email = json.email;
      profile.attestations = json.attestations;
      profile.created_at = json.created_at;

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
