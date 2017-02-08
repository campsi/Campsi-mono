//During the test the env variable is set to private
process.env.NODE_ENV = 'test';

//Require the dev-dependencies
const async = require('async');
const chai = require('chai');
const chaiHttp = require('chai-http');
const format = require('string-format');
const CampsiServer = require('../app/server');
const config = require('config');
const builder = require('../app/modules/queryBuilder');

let should = chai.should();
let server;
format.extend(String.prototype);
chai.use(chaiHttp);

// Helpers
function createPizza(data, state) {
    return new Promise(function(resolve, reject) {
        let resource = server.services.docs.options.schema.resources['pizzas'];
        builder.create({
            user: null,
            body: data,
            resource: resource,
            state: state
        }).then((doc) => {
            resource.collection.insert(doc, (err, result) => {
                resolve(result.ops[0]._id);
            });
        }).catch((error) => {
            reject(error);
        });
    });
}

// Our parent block
describe('Docs', () => {
    beforeEach((done) => { //Before each test we empty the database
        server = new CampsiServer(config);
        server.on('ready', () => {
            server.db.dropDatabase();
            console.info('ready\n');
            done();
        });
    });
    /*
     * Test the /GET docs route
     */
    describe('/GET docs', () => {
        it('it should GET all the ressources', (done) => {
            chai.request(server.app)
                .get('/docs')
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');
                    done();
                });
        });
    });
    /*
     * Test the /GET docs/pizzas route
     */
    describe('/GET docs/pizzas', () => {
        it('it should GET all the documents', (done) => {
            chai.request(server.app)
                .get('/docs/pizzas')
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');
                    res.body.count.should.be.eq(0);
                    res.body.docs.should.be.a('array');
                    res.body.docs.length.should.be.eq(0);
                    done();
                });
        });
    });
    /*
     * Test the /POST docs/pizzas route
     */
    describe('/POST docs/pizzas', () => {
        it('it should create a document', (done) => {
            let data = {"name": "test"};
            chai.request(server.app)
                .post('/docs/pizzas')
                .set('content-type', 'application/json')
                .send(data)
                .end((err, res) => {
                    res.should.have.status(403);
                    done();
                });
        });
    });
    /*
     * Test the /POST docs/pizzas route
     */
    describe('/POST docs/pizzas/:state', () => {
        it('it should create a document', (done) => {
            let data = {"name": "test"};
            chai.request(server.app)
                .post('/docs/pizzas/working_draft')
                .set('content-type', 'application/json')
                .send(data)
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');
                    res.body.state.should.be.eq('working_draft');
                    res.body.should.have.property('id');
                    console.info('Object {0} have been created'.format(res.body.id));
                    res.body.should.have.property('createdAt');
                    res.body.should.have.property('createdBy');
                    res.body.should.have.property('data');
                    res.body.data.should.be.eql(data);
                    done();
                });
        });
    });
    /*
     * Test the /GET docs/pizzas/:id route
     */
    describe('/GET docs/pizzas/:id', () => {
        it('it should retreive a document by id', (done) => {
            let data = {"name": "test"};
            createPizza(data, 'working_draft').then((id) => {
                chai.request(server.app)
                    .get('/docs/pizzas/{0}'.format(id))
                    .end((err, res) => {
                        res.should.have.status(200);
                        res.body.should.be.a('object');
                        res.body.should.have.property('id');
                        res.body.id.should.be.eq(id.toString());
                        res.body.should.have.property('state');
                        //res.body.state.should.be.eq('working_draft');
                        res.body.should.have.property('data');
                        //res.body.data.should.be.eql(data);
                        res.body.should.have.property('states');
                        res.body.states.should.be.a('object');
                        res.body.states.should.have.property('working_draft');
                        res.body.states.working_draft.should.be.a('object');
                        res.body.states.working_draft.should.have.property('createdAt');
                        res.body.states.working_draft.should.have.property('createdBy');
                        should.equal(res.body.states.working_draft.createdBy, null);
                        res.body.states.working_draft.should.have.property('data');
                        res.body.states.working_draft.data.should.be.eql(data);
                        done();
                    });
            });
        });
    });
    /*
     * Test the /GET docs/pizzas/:id/:state route
     */
    describe('/GET docs/pizzas/:id/:state', () => {
        it('it should retreive a document by id/state', (done) => {
            let data = {"name": "test"};
            createPizza(data, 'working_draft').then((id) => {
                chai.request(server.app)
                    .get('/docs/pizzas/{0}/working_draft'.format(id))
                    .end((err, res) => {
                        res.should.have.status(200);
                        res.body.should.be.a('object');
                        res.body.should.have.property('id');
                        res.body.id.should.be.eq(id.toString());
                        res.body.should.have.property('state');
                        //res.body.state.should.be.eq('working_draft');
                        res.body.should.have.property('data');
                        //res.body.data.should.be.eql(data);
                        res.body.should.have.property('states');
                        res.body.states.should.be.a('object');
                        res.body.states.should.have.property('working_draft');
                        res.body.states.working_draft.should.be.a('object');
                        res.body.states.working_draft.should.have.property('createdAt');
                        res.body.states.working_draft.should.have.property('createdBy');
                        should.equal(res.body.states.working_draft.createdBy, null);
                        res.body.states.working_draft.should.have.property('data');
                        res.body.states.working_draft.data.should.be.eql(data);
                        done();
                    });
            });
        });
    });
    /*
     * Test the /PUT docs/pizzas/:id route
     */
    describe('/PUT docs/pizzas/:id/:state', () => {
        it('it should modify a document by id/state', (done) => {
            let data = {"name": "test"};
            let modifiedData = {"name": "test put", "base": "cream"};
            createPizza(data, 'working_draft').then((id) => {
                async.series([
                    function(cb) {
                        chai.request(server.app)
                            .put('/docs/pizzas/{0}/working_draft'.format(id))
                            .set('content-type', 'application/json')
                            .send(modifiedData)
                            .end((err, res) => {
                                res.should.have.status(200);
                                res.body.should.be.a('object');
                                res.body.should.have.property('id');
                                res.body.id.should.be.eq(id.toString());
                                res.body.should.have.property('state');
                                res.body.state.should.be.eq('working_draft');
                                res.body.should.have.property('data');
                                res.body.data.should.be.eql(modifiedData);
                                cb();
                            });
                    },
                    function(cb) {
                        chai.request(server.app)
                            .get('/docs/pizzas/{0}'.format(id))
                            .end((err, res) => {
                                console.log(res.body.states);
                                res.should.have.status(200);
                                res.body.should.be.a('object');
                                res.body.should.have.property('id');
                                res.body.id.should.be.eq(id.toString());
                                res.body.should.have.property('state');
                                //res.body.state.should.be.eq('working_draft');
                                res.body.should.have.property('data');
                                //res.body.data.should.be.eql(data);
                                res.body.should.have.property('states');
                                res.body.states.should.be.a('object');
                                res.body.states.should.have.property('working_draft');
                                res.body.states.working_draft.should.be.a('object');
                                //res.body.states.working_draft.should.have.property('createdAt');
                                //res.body.states.working_draft.should.have.property('createdBy');
                                //should.equal(res.body.states.working_draft.createdBy, null);
                                //res.body.states.working_draft.should.have.property('modifyAt');
                                //res.body.states.working_draft.should.have.property('modifiedBy');
                                //should.equal(res.body.states.working_draft.modifiedBy, null);
                                res.body.states.working_draft.should.have.property('data');
                                res.body.states.working_draft.data.should.be.eql(modifiedData);
                                done();
                                cb();
                            });
                    }
                ]);
            });
        });
    });
    /*
     * Test the /PUT docs/pizzas/:id/state route
     */
    describe('/PUT docs/pizzas/:id/state', () => {
        it('it should modify a document state by id', (done) => {
            let data = {"name": "test"};
            let stateData = {'from': 'working_draft', 'to': 'published'};
            createPizza(data, 'working_draft').then((id) => {
                chai.request(server.app)
                    .put('/docs/pizzas/{0}/state'.format(id))
                    .set('content-type', 'application/json')
                    .send(stateData)
                    .end((err, res) => {
                        res.should.have.status(200);
                        res.body.should.be.a('object');
                        res.body.should.have.property('id');
                        res.body.id.should.be.eq(id.toString());
                        res.body.should.have.property('state');
                        res.body.state.should.be.eq('published');
                        res.body.should.have.property('data');
                        res.body.data.should.be.eql(stateData);
                        done();
                    });
            });
        });
    });
    /*
     * Test the /DELETE docs/pizzas/:id route
     */
    describe('/DELETE docs/pizzas/:id', () => {
        it('it should delete a document by id', (done) => {
            let data = {"name": "test"};
            createPizza(data, 'working_draft').then((id) => {
                chai.request(server.app)
                    .delete('/docs/pizzas/{0}'.format(id))
                    .end((err, res) => {
                        console.log(res.body);
                        res.should.have.status(200);
                        res.body.should.be.json();
                        res.body.should.be.a('object');
                        done();
                    });
            });
        });
        it('it should return an error when document doesn\'t exist', (done) => {
            chai.request(server.app)
                .delete('/docs/pizzas/589acbcda5756516b07cb18f')
                .end((err, res) => {
                    console.log(res.body);
                    res.should.have.status(200);
                    res.body.should.be.json();
                    res.body.should.be.a('object');
                    done();
                });
        });
        it('it should return an error when document id is malformed', (done) => {
            chai.request(server.app)
                .delete('/docs/pizzas/589acbcda57')
                .end((err, res) => {
                    console.log(res.body);
                    res.should.have.status(200);
                    res.body.should.be.json();
                    res.body.should.be.a('object');
                    done();
                });
        });
    });
});