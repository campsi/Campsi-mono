const CryptoJS = require('crypto-js');
const handlers = require('./handlers');
const helpers = require('../../../lib/modules/responseHelpers');
const state = require('./state');
const bcrypt = require('bcryptjs');
const { getUsersCollection } = require('./modules/authCollections');
const { isEmailValid, clearPasswordRateLimit, passwordRateLimitReturnAwaitImplementation } = require('./handlers');
const editURL = require('edit-url');
const { serviceNotAvailableRetryAfterSeconds } = require('../../../lib/modules/responseHelpers');
const { passwordRateLimitDefaults } = require('./defaults');
const debug = require('debug')('campsi:auth:local');

function getMissingParameters(payload, parameters) {
  return parameters.filter(paramName => typeof payload[paramName] === 'undefined');
}

function dispatchUserSignupEvent(req, user) {
  req.service.emit('signup', {
    id: user._id,
    email: user.email,
    username: user.displayName,
    firstName: user.firstName,
    lastName: user.lastName,
    token: user.identities.local.validationToken,
    data: user.data,
    authProvider: 'local',
    requestBody: req.body,
    requestHeaders: req.headers,
    invitedBy: user.invitedBy
  });
}

const localAuthMiddleware = function (localProvider) {
  return (req, res, next) => {
    req.authProvider = localProvider;
    state.serialize(req);
    next();
  };
};

/**
 * note: this works with passwordRateLimitImplementation to provide a rate
 * limit on password *FAILURES*.
 */
const passwordRateLimitMiddleware = function (_passwordRateLimits) {
  const passwordRateLimits = passwordRateLimitDefaults(_passwordRateLimits);
  return (req, res, next) => {
    const ipaddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const rateLimiterKey = passwordRateLimits.key + ':' + ipaddress;
    const redis = req.campsi.redis;
    redis.get(rateLimiterKey).then(value => {
      if (value) {
        const settings = JSON.parse(value);
        const now = new Date().getTime();
        if (settings.blockUntil && now < settings.blockUntil) {
          serviceNotAvailableRetryAfterSeconds(res, Math.ceil((settings.blockUntil - now) / 1000), null, passwordRateLimits.key);
        } else {
          next();
        }
      } else {
        next();
      }
    });
  };
};

const signin = function (req, res, next) {
  // could be a one-liner, but I find this more explicit
  // the real signin method is the callback below
  return handlers.callback(req, res, next);
};

/**
 * This method is responsible of authentificating the user based on the username
 * and password passed in arguments
 * Added 2020-11-16: email is case insensitive, but username still is.
 * @param req
 * @param username
 * @param password
 * @param done
 */
const callback = async function localCallback(req, username, password, done) {
  const filter = {
    $or: [
      {
        email: new RegExp('^' + username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i')
      },
      { 'identities.local.username': username }
    ]
  };
  try {
    const usersCollection = await getUsersCollection(req.campsi, req.service.path);
    const user = await usersCollection.findOne(filter);
    if (!user) {
      debug('tried to find user with username', username, 'but none found');
      done(null, null);
    }
    debug('signin passport callback', username, user.identities.local.encryptedPassword, filter);
    bcrypt.compare(password, user.identities.local.encryptedPassword, function (err, isMatch) {
      if (err) {
        debug('bcrypt password compare error', err, user.identities.local.encryptedPassword);
      }
      if (isMatch) {
        user.identity = user.identities.local;

        return done(null, user);
      } else {
        done(null, null);
      }
    });
  } catch (e) {
    done(e);
  }
};

const encryptPassword = function (password, saltRounds) {
  function byteLength(str) {
    // returns the byte length of an utf8 string
    let s = str.length;
    for (let i = str.length - 1; i >= 0; i--) {
      const code = str.charCodeAt(i);
      if (code > 0x7f && code <= 0x7ff) s++;
      else if (code > 0x7ff && code <= 0xffff) s += 2;
      if (code >= 0xdc00 && code <= 0xdfff) i--; // trail surrogate
    }
    return s;
  }

  return new Promise((resolve, reject) => {
    if (byteLength(password) > 72) {
      reject(new Error('Password byte length must not exceed 72 bytes'));
    }
    bcrypt.genSalt(saltRounds || 2, function (err, generatedSalt) {
      if (err) return reject(err);
      bcrypt.hash(password, generatedSalt, function (err, hash) {
        if (err) return reject(err);
        resolve(hash);
      });
    });
  });
};

const createRandomToken = function (username, salt) {
  return CryptoJS.AES.encrypt(new Date().toISOString() + username, salt).toString();
};

const signup = async function (req, res) {
  const salt = req.authProvider.options.salt;
  const passwordRegex = new RegExp(req.authProvider.options.passwordRegex ?? '.*');
  if (!passwordRegex.test(req.body.password)) {
    return helpers.error(
      res,
      new Error(`Invalid password, please respect this regex : ${req.authProvider.options.passwordRegex}`)
    );
  }
  const users = await getUsersCollection(req.campsi, req.service.path);
  const missingParameters = ['password', 'displayName', 'username'].filter(prop => {
    return typeof req.body[prop] === 'undefined' || req.body.prop === '';
  });
  if (missingParameters.length > 0) {
    return helpers.error(res, new Error(`missing parameters : ${missingParameters.join(', ')}`));
  }
  const insertUser = function (user) {
    return new Promise((resolve, reject) => {
      users
        .insertOne(user)
        .then(result => resolve(Object.assign({}, user, { _id: result.insertedId })))
        .catch(err => {
          reject(err);
        });
    });
  };
  const updateInvitedUser = async function (user, invitationToken) {
    try {
      delete user.identities.local.validationToken;
      user.identities.local.validated = true;
      const update = {
        $set: {
          'identities.local': user.identities.local,
          email: user.email,
          displayName: user.displayName,
          data: user.data,
          updatedAt: new Date()
        }
      };
      if (invitationToken) {
        update.$unset = { [`identities.invitation-${invitationToken}`]: true };
      }
      return await users.findOneAndUpdate({ email: user.email }, update, {
        returnDocument: 'after'
      });
    } catch (err) {
      throw new Error('could not perform findOneAndUpdate');
    }
  };

  const doesUserExist = async function (user) {
    try {
      return await users.findOne({ email: user.email });
    } catch (e) {
      throw new Error('could not perform findOneAndUpdate');
    }
  };

  if (req.body.email) {
    if (!isEmailValid(req.body.email)) {
      return helpers.error(res, new Error('Invalid email'));
    }
  }
  const email = String(req.body.email || req.body.username).toLowerCase();
  encryptPassword(req.body.password)
    .then(async encryptedPassword => {
      const user = {
        displayName: req.body.displayName,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email,
        data: req.body.data,
        createdAt: new Date(),
        identities: {
          local: {
            id: req.body.username,
            username: req.body.username,
            encryptedPassword,
            validated: false,
            validationToken: createRandomToken(req.body.username, salt)
          }
        }
      };

      try {
        let insertedOrUpdatedUser;
        const existingUser = await doesUserExist(user);
        if (existingUser) {
          const availableProviders = req.authProviders;
          const existingProvidersIdentities = Object.entries(existingUser.identities)
            .filter(([key, value]) => !!availableProviders[key] && !!value.id)
            .map(([key, value]) => key);

          if (existingProvidersIdentities.length) {
            const err = new Error('A user already exists with that email');
            req.campsi.logger.error(err, `[${this.constructor.name}] ${err.message}`);
            // we need to reply with a new, generic, error: F-2025-0572 - Account oracle
            // we cannot reply with a fresh auth token, which would be the normal
            // success reply.
            return helpers.badRequest(res, new Error('Bad Request'));
          }

          // user has been created, through invitation, but doesn't have any identity provider => we can update it
          const invitationToken = req.body.invitationToken;
          insertedOrUpdatedUser = await updateInvitedUser(user, invitationToken);

          if (existingUser.identities?.[`invitation-${invitationToken}`]) {
            const invitation = existingUser.identities[`invitation-${invitationToken}`];
            const payload = {
              userId: insertedOrUpdatedUser._id,
              invitedUserId: insertedOrUpdatedUser._id,
              invitedBy: invitation.invitedBy,
              data: invitation.data,
              requestHeaders: req.headers
            };
            req.service.emit('invitation/accepted', payload);
          }
        } else {
          insertedOrUpdatedUser = await insertUser(user);
        }
        handlers.callback(req, res);

        return dispatchUserSignupEvent(req, insertedOrUpdatedUser);
      } catch (err) {
        handlers.redirectWithError(req, res, err);
      }
    })
    .catch(passwordEncryptionError => {
      debug('Password encryption error', passwordEncryptionError);
      return helpers.error(res, new Error('password encryption error'));
    });
};

/**
 * Search the user that matches the validationToken
 * if found, it's marked as validated. Request is redirected
 * to the specified redirectURI.
 *
 * @param {request} req
 * @param {string} req.query.token
 * @param {string} req.query.redirectURI
 * @param {*} res
 */
const validate = async function (req, res) {
  if (!req.query.token) {
    return helpers.error(res, new Error('you must provide a validation token'));
  }

  try {
    const usersCollection = await getUsersCollection(req.campsi, req.service.path);
    const result = await usersCollection.findOneAndUpdate(
      { 'identities.local.validationToken': req.query.token },
      {
        $set: { 'identities.local.validated': true },
        $unset: { 'identities.local.validationToken': '' }
      },
      { returnDocument: 'after' }
    );
    const redirectURI = req.query.redirectURI;
    if (result) {
      req.service.emit('local/validated', {
        user: result,
        requestBody: req.body,
        requestHeaders: req.headers
      });
      req.user = result;
      debug('user validated', result);
      if (redirectURI) {
        return res.redirect(301, redirectURI);
      }
      res.json({ error: false, message: 'User is validated' });
    } else {
      if (redirectURI) {
        return res.redirect(
          editURL(redirectURI, obj => {
            obj.query.error = 'Validation Token not found';
          })
        );
      }
      helpers.notFound(res, new Error('Validation Token not found'));
    }
  } catch (err) {
    helpers.error(res, err);
  }
};

/**
 * For the record that matches identities.local.username for the given "email" in request body,
 * create a passwordResetToken with a value and expiration, that will sent as an internal event.
 *
 * It is important that this token does not go in the response, or anyone could generate token for anybody
 *
 * @param req
 * @param res
 * @return {*}
 */
const createResetPasswordToken = async (req, res) => {
  const missingParams = getMissingParameters(req.body, ['email']);
  if (missingParams.length > 0) {
    return helpers.error(res, new Error(`missing parameter(s) : ${missingParams.join(', ')}`));
  }
  try {
    const usersCollection = await getUsersCollection(req.campsi, req.service.path);
    const user = await usersCollection.findOne({
      email: new RegExp('^' + req.body.email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i')
    });
    if (!user) {
      const err = new Error('User not found');
      req.campsi.logger.error(err, `[${this.constructor.name}] ${err.message}`);
      return res.json({ success: true }); // we always reply success F-2025-0572 - Account oracle
    }

    if (!user.identities?.local?.id) {
      const availableProviders = req.authProviders;
      const existingProvidersIdentities = Object.entries(user.identities || {})
        .filter(([key, value]) => !!availableProviders[key] && !!value?.id)
        .map(([key, value]) => key);
      // user.identities can have keys not related to providers, like invitation keys, and thus can be not fully created. at this point we consider it as not found.
      const errorMessage = existingProvidersIdentities.length ? 'user does not have a local identity provider' : 'User not found';
      return helpers.forbidden(res, new Error(errorMessage));
    }
    const opts = req.authProvider.options;

    await updateUserWithPasswordResetToken(user, opts, req.db, req.service, req.body, req.headers, usersCollection);

    return res.json({ success: true });
  } catch (e) {
    return helpers.internalServerError(res, e);
  }
};

/**
 * For the given user, update its passwordResetToken, then emit an event
 * @param {object} user
 * @param {object} options
 * @param {number?} [options.resetPasswordTokenExpiration] int
 * @param {string} options.salt
 * @param {object} db
 * @param {object} service
 * @param {object} body
 * @param {object} headers
 * @param {import('mongodb').Collection} usersCollection
 */
const updateUserWithPasswordResetToken = async (user, options, db, service, body = {}, headers = {}, usersCollection) => {
  const expirationDate = new Date();
  const exp = options.resetPasswordTokenExpiration || 10;
  expirationDate.setTime(expirationDate.getTime() + exp * 86400000);

  const token = createRandomToken(user.email, options.salt);
  const out = await usersCollection.findOneAndUpdate(
    { _id: user._id },
    {
      $set: {
        'identities.local.passwordResetToken': {
          value: token,
          expiration: expirationDate
        }
      }
    },
    { returnDocument: 'after' }
  );
  service.emit('local/passwordResetTokenCreated', {
    user: out,
    requestBody: body,
    requestHeaders: headers
  });
};

/**
 * Find the user with a non-expirated passwordResetToken
 * then updates its password with the given password
 *
 * @param req
 * @param res
 * @return {*}
 */
const resetPassword = async function (req, res) {
  const missingParams = getMissingParameters(req.body, ['password', 'token']);
  const passwordRegex = new RegExp(req.authProvider.options.passwordRegex ?? '.*');
  if (!passwordRegex.test(req.body.password)) {
    return helpers.error(
      res,
      new Error(`Invalid password, please respect this regex : ${req.authProvider.options.passwordRegex}`)
    );
  }
  if (missingParams.length > 0) {
    return helpers.error(res, new Error(`missing parameter(s) : ${missingParams.join(', ')}`));
  }

  try {
    const encryptedPassword = await encryptPassword(req.body.password);
    try {
      const usersCollection = await getUsersCollection(req.campsi, req.service.path);
      const filter = {
        'identities.local.passwordResetToken.value': req.body.token,
        'identities.local.passwordResetToken.expiration': { $gt: new Date() }
      };
      const update = {
        $set: {
          'identities.local.encryptedPassword': encryptedPassword,
          tokens: {}
        },
        $unset: {
          token: '',
          passwordResetToken: ''
        }
      };
      const result = await usersCollection.findOneAndUpdate(filter, update);
      if (!result) {
        throw new Error('wrong reset token');
      }
      // we set the username as a param because if the update succeeds,
      // the request is forwarded to the passport local callback and will
      // authorize the user with the new password
      req.body.username = result.identities.local.username || result.email;
      // reset the lock on failed password attempts
      await handlers.clearPasswordRateLimit(req.authProvider.options?.passwordRateLimits, req);
      return handlers.callback(req, res);
    } catch (e) {
      handlers.redirectWithError(req, res, e);
    }
  } catch (passwordEncryptionError) {
    debug('Could not encrypt password', passwordEncryptionError);
    helpers.error({
      error: true,
      message: 'an error occurred while encrypting the password specified'
    });
  }
};

/**
 * Update the password for the current login user
 *
 * @param req
 * @param res
 * @return {*}
 */
const updatePassword = async function (req, res) {
  const missingParams = getMissingParameters(req.body, ['current', 'new', 'confirm']);
  const passwordRegex = new RegExp(req.authProvider.options.passwordRegex ?? '.*');
  if (!passwordRegex.test(req.body.new)) {
    return helpers.error(
      res,
      new Error(`Invalid password, please respect this regex : ${req.authProvider.options.passwordRegex}`)
    );
  }
  if (missingParams.length > 0) {
    return helpers.error(res, new Error(`missing parameter(s) : ${missingParams.join(', ')}`));
  }

  if (req.body.new !== req.body.confirm) {
    return helpers.error(res, new Error('new and confirmation password do not match'));
  }

  try {
    const isMatch = await new Promise((resolve, reject) =>
      bcrypt.compare(req.body.current, req.user.identities.local.encryptedPassword, function (err, isMatch) {
        if (err) {
          debug('bcrypt password compare error', err, req.user.identities.local.encryptedPassword);
          reject(err);
        } else {
          resolve(isMatch);
        }
      })
    );
    if (!isMatch) {
      const error = new Error('current password does not match.');
      const err = await passwordRateLimitReturnAwaitImplementation(
        req.authProvider.options?.passwordRateLimits,
        req,
        res,
        error,
        () => error
      );
      return helpers.error(res, err);
    }
  } catch (err) {
    return helpers.error(res, new Error('current password does not match'));
  }

  try {
    const encryptedPassword = await encryptPassword(req.body.new);
    try {
      const usersCollection = await getUsersCollection(req.campsi, req.service.path);
      const filter = { _id: req.user._id };

      const update = {
        $set: {
          'identities.local.encryptedPassword': encryptedPassword,
          tokens: {}
        },
        $unset: { token: '' }
      };

      await usersCollection.updateOne(filter, update);
      return res.json({ success: true });
    } catch (e) {
      return helpers.error(res, e);
    }
  } catch (passwordEncryptionError) {
    debug('Could not encrypt password', passwordEncryptionError);
    helpers.error({
      error: true,
      message: 'an error occurred while encrypting the new password'
    });
  }
};

module.exports = {
  localAuthMiddleware,
  passwordRateLimitMiddleware,
  signin,
  callback,
  encryptPassword,
  createRandomToken,
  signup,
  validate,
  createResetPasswordToken,
  resetPassword,
  updateUserWithPasswordResetToken,
  updatePassword
};
