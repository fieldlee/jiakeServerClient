// log4js
let log4js = require('log4js');
let logger = log4js.getLogger('HyperledgerWebApp');
// express
let express = require('express');
let session = require('express-session');
let cookieParser = require('cookie-parser');
let bodyParser = require('body-parser');
let http = require('http');
let util = require('util');

let expressJWT = require('express-jwt');
let jwt = require('jsonwebtoken');
let bearerToken = require('express-bearer-token');
let cors = require('cors');
let path = require('path');
let hfc = require('fabric-client');
let app = express();

let secretKey = "wadhotgfxgmbvsegdswtilnbczaej";
let file = 'network-config%s.json';

let env = process.env.TARGET_NETWORK;
if (env) {
	file = util.format(file, '-' + env);
} else {
	file = util.format(file, '');
}
hfc.addConfigFile(path.join(__dirname, 'config', file));
hfc.addConfigFile(path.join(__dirname, 'config', 'config.json'));


var helper = require('./app/helper.js');
var channels = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var upgrade = require('./app/update-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var query = require('./app/query.js');


let host = process.env.HOST || hfc.getConfigSetting('host');
let port = process.env.PORT || hfc.getConfigSetting('port');

app.options('*', cors());
app.use(cors());
//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
	extended: false
}));
// set secret variable
app.set('secret', secretKey);
// login 
app.use(expressJWT({ secret: secretKey }).unless({ path: ['/users'] }));
app.use(bearerToken());
app.use(function (req, res, next) {
	if (req.originalUrl.indexOf('/users') >= 0) {
		return next();
	}
	var token = req.token;
	jwt.verify(token, app.get('secret'), function (err, decoded) {
		logger.info(decoded);
		if (err) {
			res.send({
				success: false,
				info: 'Failed to authenticate token. Make sure to include the ' +
					'token returned from /users call in the authorization header ' +
					' as a Bearer token'
			});
			return;
		} else {
			// add the decoded user name and org name to the request object
			// for the downstream code to use
			req.username = decoded.username;
			req.orgname = decoded.orgName;
			logger.debug(util.format('Decoded from JWT token: username - %s, orgname - %s', decoded.username, decoded.orgName));
			return next();
		}
	});
});
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
var server = http.createServer(app).listen(port, function () { });
logger.info('****************** SERVER STARTED ************************');
logger.info('**************  http://' + host + ':' + port + '  ******************');
server.timeout = 240000;
function getErrorMessage(field) {
	var response = {
		success: false,
		info: field + ' field is missing or Invalid in the request'
	};
	return response;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////// REST ENDPOINTS START HERE ///////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Register and enroll user
app.post('/users', function (req, res) {
	var username = req.body.username;
	var password = req.body.password;
	var orgName = req.body.orgName;
	logger.debug('End point : /users');
	logger.debug('User name : ' + username);
	logger.debug('Org name  : ' + orgName);
	if (!username) {
		res.json(getErrorMessage('\'username\''));
		return;
	}
	if (!orgName) {
		res.json(getErrorMessage('\'orgName\''));
		return;
	}
	var token = jwt.sign({
		exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
		username: username,
		orgName: orgName
	}, app.get('secret'));

	helper.getRegisteredUsers(username, orgName, true, password).then(function (response) {
		if (response && typeof response !== 'string') {
			response.token = token;
			res.send(response);
		} else {
			res.json({
				success: false,
				info: response
			});
		}
	});
});

// Join Channel
app.post('/channels/peers', function (req, res) {
	logger.info('<<<<<<<<<<<<<<<<< J O I N  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName = hfc.getConfigSetting('channelName'); //channelName
	var peers = req.body.peers;
	var orgname = req.orgname;
	if (req.body.orgName) {
		orgname = req.body.orgname;
	}

	logger.debug('channelName : ' + channelName);
	logger.debug('peers : ' + peers);
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}

	join.joinChannel(channelName, peers, req.username, orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Install chaincode on target peers
app.post('/chaincodes', function (req, res) {
	logger.debug('==================== INSTALL CHAINCODE ==================');
	var peers = req.body.peers;
	var chaincodeName = req.body.chaincodeName;
	var chaincodePath = req.body.chaincodePath;
	var chaincodeVersion = req.body.chaincodeVersion;
	logger.debug('peers : ' + peers); // target peers list
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodePath  : ' + chaincodePath);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodePath) {
		res.json(getErrorMessage('\'chaincodePath\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}

	install.installChaincode(peers, chaincodeName, chaincodePath, chaincodeVersion, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Invoke transaction on chaincode on target peers
app.post('/channels/chaincodes/:chaincodeName', function (req, res) {
	logger.debug('==================== INVOKE ON CHAINCODE ==================');
	var peers = req.body.peers;
	var chaincodeName = req.params.chaincodeName;
	var channelName = hfc.getConfigSetting('channelName');
	var fcn = req.body.fcn;
	var args = req.body.args;
	logger.debug('channelName  : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('fcn  : ' + fcn);
	logger.debug('args  : ' + args);
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!fcn) {
		res.json(getErrorMessage('\'fcn\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}

	invoke.invokeChaincode(peers, channelName, chaincodeName, fcn, args, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// post Query on chaincode on target peers
app.post('/query/channels/chaincodes/:chaincodeName', function (req, res) {
	logger.debug('==================== QUERY BY CHAINCODE ==================');
	var channelName = hfc.getConfigSetting('channelName');
	var chaincodeName = req.params.chaincodeName;
	let args = req.body.args;
	let fcn = req.body.fcn;
	let peer = req.body.peer;

	logger.debug('channelName : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('fcn : ' + fcn);
	logger.debug('args : ' + args);

	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!fcn) {
		res.json(getErrorMessage('\'fcn\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}
	// args = args.replace(/'/g, '"');
	// args = JSON.parse(args);
	// logger.debug(args);

	query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
//  Query Get Block by BlockNumber
app.get('/channels/blocks/:blockId', function (req, res) {
	logger.debug('==================== GET BLOCK BY NUMBER ==================');
	let blockId = req.params.blockId;
	let peer = req.query.peer;
	logger.debug('channelName : ' + hfc.getConfigSetting('channelName'));
	logger.debug('BlockID : ' + blockId);
	logger.debug('Peer : ' + peer);
	if (!blockId) {
		res.json(getErrorMessage('\'blockId\''));
		return;
	}

	query.getBlockByNumber(peer, blockId, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Query Get Transaction by Transaction ID
app.get('/channels/transactions/:trxnId', function (req, res) {
	logger.debug(
		'================ GET TRANSACTION BY TRANSACTION_ID ======================'
	);
	logger.debug('channelName : ' + hfc.getConfigSetting('channelName'));
	let trxnId = req.params.trxnId;
	let peer = req.query.peer;
	if (!trxnId) {
		res.json(getErrorMessage('\'trxnId\''));
		return;
	}
	query.getTransactionByID(peer, trxnId, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Query Get Block by Hash
app.get('/channels/blocks', function (req, res) {
	logger.debug('================ GET BLOCK BY HASH ======================');
	logger.debug('channelName : ' + hfc.getConfigSetting('channelName'));
	let hash = req.query.hash;
	let peer = req.query.peer;
	if (!hash) {
		res.json(getErrorMessage('\'hash\''));
		return;
	}

	query.getBlockByHash(peer, hash, req.username, req.orgname).then(
		function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
//Query for Channel Information
app.get('/channels/chaininfo', function (req, res) {
	logger.debug(
		'================ GET CHANNEL INFORMATION ======================');
	logger.debug('channelName : ' + hfc.getConfigSetting('channelName'));
	let peer = req.query.peer;

	query.getChainInfo(peer, req.username, req.orgname).then(
		function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Query to fetch all Installed/instantiated chaincodes
app.get('/chaincodes', function (req, res) {
	var peer = req.query.peer;
	var installType = req.query.type;
	//TODO: add Constnats
	if (installType === 'installed') {
		logger.debug(
			'================ GET INSTALLED CHAINCODES ======================');
	} else {
		logger.debug(
			'================ GET INSTANTIATED CHAINCODES ======================');
	}

	query.getInstalledChaincodes(peer, installType, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Query to fetch channels
app.get('/channels', function (req, res) {
	logger.debug('================ GET CHANNELS ======================');
	logger.debug('peer: ' + req.query.peer);
	var peer = req.query.peer;
	if (!peer) {
		res.json(getErrorMessage('\'peer\''));
		return;
	}
	query.getChannels(peer, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});