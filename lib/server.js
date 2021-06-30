const CampsiService = require('./service');
const responseHelpers = require('./modules/responseHelpers');
const debug = require('debug')('campsi');
const MQTTEmitter = require('mqtt-emitter');
const express = require('express');
const async = require('async');
const forIn = require('for-in');
const {MongoClient} = require('mongodb');
const {URL} = require('url');

// middlewares
const cors = require('cors');
const bodyParser = require('body-parser');

function ServiceException (path, service, message) {
  this.name = 'Service exception';
  this.message = message;
  this.path = path;
  this.service = service;
}

/**
 * @property {Db} db
 */
class CampsiServer extends MQTTEmitter {
  constructor (config) {
    super();
    this.app = express();
    this.config = config;
    this.url = new URL(this.config.publicURL);
    this.services = new Map();
  }

  listen () {
    return this.app.listen(...arguments);
  }

  mount (path, service) {
    if (!/^[a-z]*$/.test(path)) {
      throw new ServiceException(path, service, 'Path is malformed');
    }
    if (!(service instanceof CampsiService)) {
      throw new ServiceException(path, service, 'Service is not a CampsiService');
    }
    if (this.services.has(path)) {
      throw new ServiceException(path, service, 'Path already exists');
    }
    this.services.set(path, service);
  }

  start () {
    return this.dbConnect()
      .then(() => this.setupApp())
      .then(() => this.loadServices())
      .then(() => this.describe())
      .then(() => this.finalizeSetup());
  }

  dbConnect () {
    const campsiServer = this;
    return new Promise((resolve, reject) => {
      const mongoUri = campsiServer.config.mongo.uri;
      MongoClient.connect(mongoUri, { useNewUrlParser: true }, (err, client) => {
        if (err) return reject(err);
        campsiServer.db = client.db(campsiServer.config.mongo.database);
        resolve();
      });
    });
  }

  setupApp () {
    this.app.use(cors());
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.text());
    this.app.use(bodyParser.urlencoded({extended: false}));
    this.app.use((req, res, next) => {
      req.campsi = this;
      req.db = this.db;
      req.config = this.config;
      next();
    });
    this.app.use((req, res, next) => {
      res.header('X-powered-by', 'campsi');
      next();
    });
    for (let service of this.services.values()) {
      let middlewares = service.getMiddlewares();
      for (let middleware of middlewares) {
        this.app.use(middleware(this, service));
      }
    }
  }

  loadServices () {
    return new Promise((resolve) => {
      async.eachOf(this.services, (value, key, cb) => {
        let path = value[0];
        let service = value[1];
        service.server = this;
        service.db = this.db;
        service.path = path;
        service.initialize().then(() => {
          let serviceFullPath = this.url.pathname === '/' ? '/' + path : this.url.pathname + '/' + path;
          this.app.use(serviceFullPath, service.router);
          cb();
        }).catch((err) => {
          debug('Loading services error: %s', err.message);
        });
      }, resolve);
    });
  }

  describe () {
    this.app.get(this.url.pathname, (req, res) => {
      let result = {
        title: this.config.title,
        services: {}
      };
      forIn(this.services, (service, path) => {
        result.services[path] = service.describe();
      });
      res.json(result);
    });
  }

  finalizeSetup () {
    this.app.use((req, res) => {
      debug('Final handler');
      responseHelpers.notFound(res, new Error(`C'ant find ${req.method} ${req.path}`));
    });
    this.emit('campsi/ready');
  }
}

module.exports = CampsiServer;
