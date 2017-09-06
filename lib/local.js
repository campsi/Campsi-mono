const CryptoJS = require('crypto-js');
const handlers = require('./handlers');
const helpers = require('campsi/lib/modules/responseHelpers');
const state = require('./state');

function testPassword(provider, user, password) {
    const decrypted = CryptoJS.AES.decrypt(
        user.identities.local.password,
        provider.options.salt
    ).toString(CryptoJS.enc.Utf8);
    return password === decrypted;
}

module.exports.middleware = function (localProvider) {
    return (req, res, next) => {
        req.authProvider = localProvider;
        state.serialize(req);
        next();
    };
};

module.exports.signin = function (req, res) {
    // could be a one-liner, but I find this more explicit
    return handlers.callback(req, res);
};

module.exports.signup = function (req, res) {
    const localProvider = req.authProvider;
    if(!req.body.password || !req.body.displayName || !req.body.username) {
        return helpers.error(res, {message: 'bad request'});
    }

    const encryptedPassword = CryptoJS.AES.encrypt(
        req.body.password,
        localProvider.options.salt
    ).toString();

    let user = {
        displayName: req.body.displayName,
        email: req.body.email || req.body.username,
        identities: {
            local: {
                id: req.body.username,
                username: req.body.username,
                password: encryptedPassword
            }
        }
    };

    req.db.collection('__users__').insertOne(user)
        .then(() => handlers.callback(req, res))
        .catch((err) => handlers.redirectWithError(req, res, err));
};

module.exports.resetPassword = function (req, res) {
    if(!req.body.password) {
        return helpers.error(res, {message: 'bad request'});
    }

    if(!req.user) {
        return helpers.serviceNotAvailable(res);
    }

    const localProvider = req.authProvider;
    const encryptedPassword = CryptoJS.AES.encrypt(
        req.body.password,
        localProvider.options.salt
    ).toString();

    let filter = { _id : req.user._id };
    let update = { $set : { 'identities.local.password' : encryptedPassword }, $unset : { 'token' : '' }};

    req.body.username = req.user.identities.local.username;
    delete(req.user);

    req.db.collection('__users__').updateOne(filter, update)
        .then(() => handlers.callback(req, res))
        .catch((err) => handlers.redirectWithError(req, res, err));
};

module.exports.callback = function localCallback(req, username, password, done) {
    let filter = {};
    filter['identities.local.username'] = username;
    req.db.collection('__users__').findOne(filter).then((user) => {
        if (user && user.identities.local && testPassword(req.authProvider, user, password)) {
            user.identity = user.identities.local;
            return done(null, user);
        }
        done(null, null);
    }).catch(done);
};
