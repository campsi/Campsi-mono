/**
 * Created by romain on 06/12/2016.
 */

const debug = require('debug')('campsi');
const builder = require('./modules/queryBuilder');
const helpers = require('campsi/lib/modules/responseHelpers');
const embedDocs = require('./modules/embedDocs');
const paginateCursor = require('campsi/lib/modules/paginateCursor');
const sortCursor = require('campsi/lib/modules/sortCursor');
const sendWebhook = require('./modules/sendWebhook');
const forIn = require('for-in');

const onUpdate = (req, res) => (err, result) => {
    if (err) {
        return helpers.error(res, err);
    }

    if (result.modifiedCount !== 1) {
        return helpers.notFound(res);
    }

    const output = {
        id: req.params.id,
        state: req.state,
        data: req.body
    };
    helpers.json(res, output);
    sendWebhook(req, output);
};

module.exports.getDocs = function (req, res) {

    const queryBuilderOptions = {
        resource: req.resource,
        user: req.user,
        query: req.query,
        state: req.state
    };

    const query = builder.find(queryBuilderOptions);
    const fields = builder.select(queryBuilderOptions);

    const cursor = req.resource.collection.find(query, fields);

    let result = {};
    let perPage = req.resource.perPage || 100;
    cursor.count().then((count) => {
        result.count = count;
        result.label = req.resource.label;
        let {skip, limit, page} = paginateCursor(cursor, req.query, {perPage: perPage});
        result.hasNext = result.count > skip + limit;
        result.hasPrev = skip > 0;
        result.perPage = perPage;
        result.page = page;
        result.pageCount = Math.ceil(count / perPage);
        sortCursor(cursor, req);
        return cursor.toArray();
    }).then((docs) => {
        result.docs = docs.map((doc) => {
            const fallbackState = Object.keys(doc.states)[0];
            const currentState = doc.states[req.state] || doc.states[fallbackState];
            return {
                id: doc._id,
                state: doc.states[req.state] ? req.state : fallbackState,
                states: doc.states,
                createdAt: currentState.createdAt,
                createdBy: currentState.createdBy,
                data: currentState.data || {},
            };
        });
        return embedDocs.many(req, result.docs);
    }).then(() => res.json(result)).catch((err) => {
        debug('Error: %s', err);
        res.json({});
    });
};
Object.defineProperty(module.exports.getDocs, 'apidoc', {value: {
    summary: 'Get documents'
}});

module.exports.postDoc = function (req, res) {
    builder.create({
        user: req.user,
        body: req.body,
        resource: req.resource,
        state: req.state
    }).then((doc) => {
        req.resource.collection.insert(doc, (err, result) => {
            let output = Object.assign({
                state: req.state,
                id: result.ops[0]._id
            }, result.ops[0].states[req.state]);

            helpers.json(res, output);
            sendWebhook(req, output);
        });
    }).catch(helpers.validationError(res));
};

// get all states of a document
module.exports.getDocState = function (req, res) {
    const fields = builder.getStates({
        resource: req.resource,
        user: req.user,
        query: req.query,
        state: req.state
    });

    req.resource.collection.findOne(req.filter, fields, (err, doc) => {
        if (doc === null) {
            return helpers.notFound(res);
        }

        const returnValue = {
            id: doc._id,
            states: doc.states,
        };

        helpers.json(res, returnValue);
    });
};

// modify the state of a doc
module.exports.putDocState = function (req, res) {

    const doSetState = function () {
        builder.setState({
            doc: req.doc,
            from: req.body.from,
            to: req.body.to,
            resource: req.resource,
            user: req.user
        }).then((ops) => {
            req.resource.collection.updateOne(req.filter, ops, onUpdate(req, res));
        }).catch(helpers.validationError(res));
    };

    const stateTo = req.resource.states[req.body.to];
    const stateFrom = req.resource.states[req.body.from];

    if (typeof stateTo === 'undefined') {
        helpers.error(res, {message: 'Undefined state', state: req.body.to});
    }

    if (typeof stateFrom === 'undefined') {
        helpers.error(res, {message: 'Undefined state', state: req.body.from});
    }

    if (!stateTo.validate) {
        return doSetState();
    }

    req.resource.collection.findOne(req.filter, (err, doc) => {
        req.doc = doc.states[req.body.from].data;
        doSetState();
    });
};

// modify a doc
module.exports.putDoc = function (req, res) {
    builder.update({
        body: req.body,
        resource: req.resource,
        state: req.state,
        user: req.user
    }).then((ops) => {
        req.resource.collection.updateOne(req.filter, ops, onUpdate(req, res));
    }).catch((err) => {
        return helpers.error(res, err);
    });
};

// get a doc
module.exports.getDoc = function (req, res) {
    let requestedStates = req.query.states;
    requestedStates = requestedStates === '' ? Object.keys(req.resource.states) : requestedStates;
    requestedStates = requestedStates === undefined ? [] : requestedStates;
    requestedStates = Array.isArray(requestedStates) ? requestedStates : [requestedStates];

    const fields = builder.select({
        method: 'GET',
        resource: req.resource,
        user: req.user,
        query: req.query,
        state: [...new Set(requestedStates.concat(req.state))]
    });

    req.resource.collection.findOne(req.filter, fields, (err, doc) => {
        if (doc === null) {
            return helpers.notFound(res);
        }
        if (doc.states[req.state] === undefined) {
            return helpers.notFound(res);
        }

        const currentState = doc.states[req.state] || {};
        const returnValue = {
            id: doc._id,
            state: req.state,
            createdAt: currentState.createdAt,
            createdBy: currentState.createdBy,
            modifiedAt: currentState.modifiedAt,
            modifiedBy: currentState.modifiedBy,
            data: currentState.data || {},
        };

        if(requestedStates.length > 0) {
            returnValue.states = Object.keys(doc.states)
                .filter(docState => requestedStates.includes(docState))
                .reduce((displayStates, displayState) => {
                    displayStates[displayState] = doc.states[displayState];
                    return displayStates;
                }, {});
        }

        embedDocs.one(req, returnValue.data)
            .then(() => helpers.json(res, returnValue));
    });
};

module.exports.delDoc = function (req, res) {
    const statePath = ['states', req.state].join('.');
    let updateParams = {$unset: {}};
    updateParams.$unset[statePath] = '';
    req.resource.collection.findOneAndUpdate(req.filter, updateParams, (err, out) => {
        if (err) {
            return helpers.error(err);
        }
        if (out.lastErrorObject.n === 0) {
            return helpers.notFound(res);
        }
        let filter = builder.deleteFilter({id: out.value._id});
        req.resource.collection.findOneAndDelete(filter, () => {
            return helpers.json(res, {'message': 'OK'});
        });
    });
};

module.exports.getResources = function (req, res) {
    let result = {resources: []};
    forIn(req.options.resources, (resource, id) => {
        result.resources.push({
            id: id,
            label: resource.label,
            type: resource.type,
            states: resource.states,
            defaultState: resource.defaultState,
            permissions: resource.permissions,
            schema: resource.schema
        });
    });

    result.classes = req.options.classes;

    helpers.json(res, result);
};
Object.defineProperty(module.exports.getResources, 'apidoc', {value: {
    summary: 'Get all resources',
    description: 'List all resources from schema.'
}});
