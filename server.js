'use strict';

// Module imports
var log = require('npmlog-ts')
  , util = require('util')
  , async = require('async')
  , express = require('express')
  , cors = require('cors')
  , restify = require('restify-clients')
  , http = require('http')
  , bodyParser = require('body-parser')
  , _ = require('lodash')
  , commandLineArgs = require('command-line-args')
  , getUsage = require('command-line-usage')
  , FBMessenger = require('fb-messenger');
  , basicAuth = require('express-basic-auth')
  , passwordHash = require('password-hash')
;

// Misc BEGIN
const PROCESSNAME = "Wedo Hospitality Demo - Facebook Messenger Push Gateway"
    , VERSION  = "v1.0"
    , AUTHOR   = "Carlos Casares <carlos.casares@oracle.com>"
    , PROCESS  = 'PROCESS'
    , REST     = 'REST'
    , DB       = 'DB'
    , FACEBOOK = 'FACEBOOK'
    , username = 'admin';
    , hashedPassword = 'sha1$13c9bd8d$1$84c1280f31e01d62bb77d7e3b17c2333086d8042';
;

log.timestamp = true;
// Misc END

// Initialize input arguments
const optionDefinitions = [
  { name: 'dbhost', alias: 'd', type: String },
  { name: 'help', alias: 'h', type: Boolean },
  { name: 'verbose', alias: 'v', type: Boolean, defaultOption: false }
];

const sections = [
  {
    header: PROCESSNAME,
    content: ''
  },
  {
    header: 'Options',
    optionList: [
      {
        name: 'dbhost',
        typeLabel: '[underline]{hostname/IP}',
        alias: 'd',
        type: String,
        description: 'DB Hostname for setup'
      },
      {
        name: 'verbose',
        alias: 'v',
        description: 'Enable verbose logging.'
      },
      {
        name: 'help',
        alias: 'h',
        description: 'Print this usage guide.'
      }
    ]
  }
]
var options = undefined;

try {
  options = commandLineArgs(optionDefinitions);
} catch (e) {
  console.log(getUsage(sections));
  console.log(e.message);
  process.exit(-1);
}

if (options.help || !options.dbhost) {
  console.log(getUsage(sections));
  process.exit(0);
}

log.level = (options.verbose) ? 'verbose' : 'info';

const GETUSERURI = '/ords/pdb1/smarthospitality/customer/social/%s'
;

var dbClient = restify.createJsonClient({
  url: 'https://' + options.dbhost,
  rejectUnauthorized: false,
  headers: {
    "content-type": "application/json"
  }
});

// Initializing REST & WS variables BEGIN
const PORT = 3666
    , CONTEXTROOT = '/messenger'
    , SENDURI     = '/send/:socialid'
;

var app    = express()
  , router = express.Router()
  , server = http.createServer(app)
  , messenger = _.noop()
;
// Initializing REST & WS variables END

// Facebook stuff
const token       = 'EAAFCo0ZB9MN4BAF3DPAT76WwsTeORmYBZCb7cCvVKlDZBqHOVTNHx7ObdYByMQDY5bTnShmjyceZAcqSSSZCtwjgZBeIoVHwOTWuXrFyB48zNWRwndjZAlrTJJVNydqkK7WRHZB5ky0ZBOnlptyXo1ZAIAbBnbUEBuOp57Q5IFZCzDoDwZDZD'
    , REGULAR     = 'REGULAR'
    , SILENT_PUSH = 'SILENT_PUSH'
    , NO_PUSH     = 'NO_PUSH'
;

// Main handlers registration - BEGIN
// Main error handler

process.on('uncaughtException', function (err) {
  console.log("Uncaught Exception: " + err);
  console.log("Uncaught Exception: " + err.stack);
});

process.on('SIGINT', function() {
  log.info(PROCESS, "Caught interrupt signal");
  log.info(PROCESS, "Exiting gracefully");
  process.removeAllListeners()
  if (typeof err != 'undefined')
    log.error(PROCESS, err)
  process.exit(2);
});
// Main handlers registration - END

// Main initialization code

async.series( {
  splash: function(callbackMainSeries) {
    log.info(PROCESS, "%s - %s", PROCESSNAME, VERSION);
    log.info(PROCESS, "Author - %s", AUTHOR);
    callbackMainSeries(null);
  },
  messenger: function(callbackMainSeries) {
    messenger = new FBMessenger(token, REGULAR);
    callbackMainSeries(null);
  },
  rest: function(callbackMainSeries) {
    log.info(REST, "Initializing REST Server");
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(bodyParser.json());
    app.use(basicAuth( { authorizer: myAuthorizer } ));
    app.use(cors());
    app.use(CONTEXTROOT, router);
    router.post(SENDURI, function(req, res) {
      if (!req.params.socialid) {
        var msg = "Missing socialid";
        log.error(REST, msg);
        res.status(400).send(msg);
        return;
      }
      if (!req.body || !req.body.message) {
        var msg = "Missing message payload";
        log.error(REST, msg);
        res.status(400).send(msg);
        return;
      }

      if (req.body.mode) {
        if ( typeof(req.body.mode.push) !== "boolean" || typeof(req.body.mode.sound) !== "boolean" ) {
          var msg = "Wrong modes";
          log.error(REST, msg);
          res.status(400).send(msg);
          return;
        }
      }

      log.verbose(REST, "Request for user %s: %j", req.params.socialid, req.body)

      var URI = util.format(GETUSERURI, encodeURIComponent(req.params.socialid));
      dbClient.get(URI, function(_err, _req, _res, _obj) {
        if (_err) {
          log.error(DB, _err.message);
          res.status(500).send(_err.message);
        } else {
          if (!_res.body) {
            var msg = "Error retrieving user data from database";
            log.error(DB, msg);
            res.status(500).send(msg);
            return;
          }
          var jBody = JSON.parse(_res.body);
          if (!jBody.items || jBody.items.length == 0) {
            var msg = util.format("User %s not found/registered", req.params.socialid);
            log.error(DB, msg);
            res.status(400).send(msg);
            return;
          }
          if (!jBody.items[0].socialinternalid) {
            var msg = util.format("User %s does not have a FCBK internal ID associated", req.params.socialid);
            log.error(DB, msg);
            res.status(400).send(msg);
            return;
          }

          if (messenger) {
            var mode = REGULAR;
            if (req.body.mode) {
              if (req.body.mode.push === true && req.body.mode.sound === true) {
                mode = REGULAR;
              } else if (req.body.mode.push === true && req.body.mode.sound === false) {
                mode = SILENT_PUSH;
              } else if (req.body.mode.push === false && req.body.mode.sound === false) {
                mode = NO_PUSH;
              }
            }
            log.verbose(FACEBOOK, "Sending [%s] message to %s (%s)", mode, req.params.socialid, jBody.items[0].socialinternalid);
            messenger.sendTextMessage(jBody.items[0].socialinternalid, req.body.message, mode, (__err, body) => {
              if (__err) {
                log.error(FACEBOOK, __err.message);
                res.status(500).send(__err.message);
                return;
              }
              if (body.message_id) {
                log.verbose(FACEBOOK, "Message sent successfully");
              }
              res.status(204).end();
            });
          }
        }
      });
    });
    server.listen(PORT, function() {
      log.info(REST, "REST Server initialized successfully at http://localhost:%d%s", PORT, CONTEXTROOT + SENDURI);
      callbackMainSeries(null);
    });
  }
}, function(err, results) {
  if (err) {
    log.error("Error during initialization: " + err);
  } else {
    log.info(PROCESS, 'Initialization completed');
  }
});

function myAuthorizer(_username, _password) {
    return (_username === username) && passwordHash.verify(_password, hashedPassword);
}
