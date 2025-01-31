const CampsiService = require('../../../lib/service');
const local = require('./local');
const libRateLimit = require('../../../lib/middlewares/rateLimit');
const passportMiddleware = require('./passportMiddleware');
const passport = require('@passport-next/passport');
const helpers = require('../../../lib/modules/responseHelpers');
const handlers = require('./handlers');
const debug = require('debug')('campsi');
const authUser = require('./middleware/authUser');
const session = require('./middleware/session');
const createObjectId = require('../../../lib/modules/createObjectId');
const createError = require('http-errors');

module.exports = class AuthService extends CampsiService {
  initialize() {
    this.install();
    this.prepareAuthProviders();
    this.patchRouter();
    return super.initialize();
  }

  prepareAuthProviders() {
    // eslint-disable-next-line array-callback-return
    Object.entries(this.options.providers).map(([name, provider]) => {
      provider.options.passReqToCallback = true;
      provider.options.scope = provider.scope;
      provider.name = name;
      if (name === 'local') {
        provider.callback = local.callback;
      }
      // noinspection JSUnresolvedFunction
      passport.use(name, new provider.Strategy(provider.options, passportMiddleware));
    });
  }

  // eslint-disable-next-line max-statements
  patchRouter() {
    const router = this.router;
    const providers = this.options.providers;
    this.router.use((req, res, next) => {
      req.authProviders = providers;
      req.service = this;
      next();
    });

    const localSignupMiddleware = (req, res, next) =>
      typeof this.options.localSignupMiddleware !== 'function' ? next() : this.options.localSignupMiddleware(req, res, next);

    this.router.use(passport.initialize());
    this.router.param('provider', (req, res, next, id) => {
      req.authProvider = providers[id];
      return !req.authProvider ? helpers.notFound(res) : next();
    });
    const limiter = this.server.limiter || ((req, res, next) => next());

    const validatePasswordResetUrl = (req, res, next) => {
      if (typeof this.options.validatePasswordResetUrl !== 'function') {
        return next();
      }
      return next(this.options.validatePasswordResetUrl(req.body?.resetUrl) ? null : createError(400, 'Invalid reset URL'));
    };

    const validateRedirectURI = (req, res, next) => {
      if (typeof this.options.validateRedirectURI !== 'function') {
        return next();
      }
      return next(this.options.validateRedirectURI(req.query.redirectURI) ? null : createError(400, 'invalid redirectURI'));
    };

    router.get('/users', handlers.getUsers);
    router.get('/users/:userId/extract_personal_data', handlers.extractUserPersonalData);
    router.get('/users/:userId/access_token', handlers.getAccessTokenForUser);

    router.delete('/users/:userId[:]soft-delete', handlers.softDelete);

    router.get('/providers', handlers.getProviders);
    router.get('/me', validateRedirectURI, handlers.me);
    router.put('/me', handlers.updateMe);
    router.patch('/me', handlers.patchMe);
    if (process.env.NODE_ENV !== 'production') {
      // used by end-to-end tests
      router.delete('/me', handlers.deleteMe);
    }
    router.get('/anonymous', handlers.createAnonymousUser);
    router.get('/logout', handlers.logout);
    router.post('/invitations', handlers.inviteUser);
    router.get('/invitations/:invitationToken', limiter, handlers.getUserByInvitationToken);
    router.post('/invitations/:invitationToken', handlers.acceptInvitation);
    router.delete('/invitations/:invitationToken', handlers.deleteInvitation);
    router.put('/tokens', handlers.tokenMaintenance);

    if (providers.local) {
      router.use(
        '/local',
        libRateLimit.rateLimitMiddleware(providers.local.options?.rateLimits),
        local.localAuthMiddleware(providers.local)
      );
      router.post('/local/signup', localSignupMiddleware, local.signup);
      router.post('/local/signin', local.passwordRateLimitMiddleware(providers.local.options?.passwordRateLimits), local.signin);
      router.post('/local/reset-password-token', validatePasswordResetUrl, local.createResetPasswordToken);
      router.post('/local/reset-password', local.resetPassword);
      router.get('/local/validate', local.validate);
      router.put(
        '/local/update-password',
        local.passwordRateLimitMiddleware(providers.local.options?.passwordRateLimits),
        local.updatePassword
      );
    }
    this.router.get('/:provider', handlers.initAuth);
    this.router.get('/:provider/callback', handlers.callback);
  }

  getMiddlewares() {
    return [session, authUser];
  }

  install() {
    this.db
      .collection(this.getUsersCollectionName())
      .createIndex({ email: 1 }, { unique: true })
      .catch(err => {
        debug("Can't apply unique index on users collection");
        debug(err);
      });
    if (this.options.providers.local) {
      this.db
        .collection(this.getUsersCollectionName())
        .createIndex({ 'identities.local.validationToken': 1 })
        .catch(err => debug(err));
    }
  }

  async fetchUsers(userIds) {
    const filter = { _id: { $in: userIds.map(id => createObjectId(id)) } };
    const users = await this.db.collection(this.getUsersCollectionName()).find(filter).toArray();
    const map = users.reduce((map, user) => {
      map[user._id.toString()] = user;
      return map;
    }, {});
    return userIds.map(userId => map[userId] || userId);
  }

  getUsersCollectionName() {
    return this.options?.collectionName || '__users__';
  }

  getSessionCollectionName() {
    return this.options?.session?.collectionName || '__sessions__';
  }
};
