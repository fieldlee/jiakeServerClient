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
let netConfig = hfc.getConfigSetting('network-config');
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
function responseJson(code,msg,data={}) {
    return {
        code : code,
        msg : msg,
        data : data
    };
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
				logger.info(message);
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
				logger.info(message);
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
				logger.info(message);
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
				logger.info(message);
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
				logger.info(message);
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
				logger.info(message);
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
				logger.info(message);
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


app.post('/channels/query/init', function (req, res) {
    let result = {
        count:{peer_count:0,
            block_count:0,
            transaction_count:0,
            chaincode_count:0},
        peers:[]
    };
    let allThread = 4;
    let currentCount =0;
    try{
        function callback() {
            if(currentCount>=allThread){
                res.json(responseJson(200,'ok',result));
            }
        }
        function peerCount(f){
            let j = 0;
            for ( let k in netConfig) {
                if(netConfig[k].peers){
                    for (let key in netConfig[k].peers) {
                        let peer = netConfig[k].peers[key];
                        result.count.peer_count++;
                        result.peers[j++] = {
                            index : j,
                            address : peer.requests,
                            orgname : netConfig[k].name,
                            mspid : netConfig[k].mspid
                        };
                    }
                }
            }
            currentCount++;
            f();
        }
        async function chainCodeCount(f){
            let r = await query.getChainInfo(req.body.peer,req.username,req.orgname);
            result.count.block_count = r.height.low;
            let chaincodes = await query.getInstalledChaincodes(req.body.peer,"installed",req.username,req.orgname);
            let tmpName = "";
            for ( let id in chaincodes ) {
                let strs = chaincodes[id].split(",");
                if(tmpName.toString() !== strs[0].toString()){
                    tmpName = strs[0].toString();
                    result.count.chaincode_count++;
                }
            }
            currentCount += 2;
            f();
        }
        async function transactionCount(f){
            let channelName = hfc.getConfigSetting('channelName');
            let chaincodeName = "jiakechaincode";
            let args = [];
            let fcn = "querytxcount";
            let peer = req.body.peer;
            let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname);
            message = message.split("now has")[1];
            message = message.split("after the move")[0];
            let jmsg = JSON.parse(message);
            result.count.transaction_count = jmsg.count;
            console.log("==========================*****************************************",jmsg);
            currentCount++;
            f();
        }
        peerCount(callback);
        chainCodeCount(callback);
        transactionCount(callback);
	}
	catch (e) {
        res.json(responseJson(400,'初始化失败',result));
    }

});
app.post('/channels/query/blocks', function (req, res) {
    let pageSize = req.query.pageSize;
    if (!pageSize) {
        pageSize = 10;
    }
    if (!req.query.hight) {
        res.json(responseJson(400,'最后高度没传'));
    }
    let result = [];
    let currentCount =0;
    function callback() {
        if(currentCount>=pageSize){
            res.json(responseJson(200,'ok',result));
        }
    }
    async function getBlock(callback,i){
        let ch = req.query.hight - i;
        try{
            let r = await query.getBlockByNumber(req.body.peer,ch,req.username,req.orgname);
            let date = new Date(r.data.data[0].payload.header.channel_header.timestamp);
            let time = date.getTime();//转换成秒
            result[i] = {
                "number" : r.header.number,
                "previous_hash" : r.header.previous_hash,
                "data_hash" : r.header.data_hash,
                "tx_count" : r.data.data.length,
                "timestamp" : time
            };
            currentCount++;
            callback();
        }
        catch (e) {
            console.log("========================wrong");
            currentCount++;
            callback();
        }
    }
    for (let i=0;i<pageSize;i++){
        getBlock(callback,i);
    }
});
app.post('/channels/query/chaincode/:chaincodeName', async function (req, res) {
    logger.debug('==================== QUERY BY CHAINCODE ==================');
    let channelName = hfc.getConfigSetting('channelName');
    let chaincodeName = req.params.chaincodeName;
    let args = req.body.args;
    let fcn = req.body.fcn;
    let peer = req.body.peer;

    if (!chaincodeName) {
        res.json(responseJson(400,'chaincodeName 不能为空！'));
        return;
    }
    if (!channelName) {
        res.json(responseJson(400,'channelName 不能为空！'));
        return;
    }
    if (!fcn) {
        res.json(responseJson(400,'fcn 不能为空！'));
        return;
    }
    if (!args) {
        res.json(responseJson(400,'args 不能为空！'));
        return;
    }
    try{
        let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname);
        message = message.split("now has")[1];
        message = message.split("after the move")[0];
        if (message && typeof message !== 'string') {
            res.json(responseJson(400,"查询交易出错!",message));
            return true;
        }
        let jmsg = JSON.parse(message);
        if(fcn.toString()==="querytransfer"){
            for (let i=0;i<jmsg.length;i++){
                jmsg[i]["operateTime"] = jmsg[i]["operateTime"] * 1000;
			}
		}

        if (jmsg && typeof jmsg !== 'string') {
            res.json(responseJson(200,'ok',jmsg));
            return true;
        }
        res.json(responseJson(400,"查询交易出错!"));
        return true;
    }
    catch (e) {
        res.json(responseJson(400,'查询交易出错',e));
    }

});
app.post('/channels/query/block/:blockId', function (req, res) {
    let blockId = req.params.blockId;
    if (!blockId) {
        res.json(responseJson(400,'区块id错误'));
    }
    let result = [];
    async function getBlock(){
        try{
            let r = await query.getBlockByNumber(req.body.peer,blockId,req.username,req.orgname);
            for (let j=0;j<r.data.data.length;j++){
                console.log("========================data===================",blockId);
                let rwWrites = r.data.data[j].payload.data.actions[0].payload.action.proposal_response_payload.extension.results.ns_rwset;
                result.push.apply(result,getBlockTransData(rwWrites));
                console.log("***********************",result,"******************");
            }
            res.json(responseJson(200,'ok',result));
        }
        catch (e) {
            console.log("========================wrong==========================",e);
            res.json(responseJson(404,'未发现相关区块',result));
        }
    }
    getBlock();
});
app.post('/channels/query/transaction/:txid', function (req, res) {
    let txid = req.params.txid;
    if (!txid) {
        res.json(responseJson(400,'交易编号错误'));
    }
    let result = [];
    async function getBlock(){
        try{
            let r = await query.getTransactionByID(req.body.peer,txid,req.username,req.orgname);

            if(r.validationCode!==0){
                res.json(responseJson(400,'未发现数据'));
			}
            console.log("========================data===================",txid);
            let rwWrites = r.transactionEnvelope.payload.data.actions[0].payload.action.proposal_response_payload.extension.results.ns_rwset;
            res.json(responseJson(200,'ok',getBlockTransData(rwWrites)));
        }
        catch (e) {
            console.log("========================wrong==========================",e);
            res.json(responseJson(404,'未发现相关区块',result));
        }
    }
    getBlock();
});


function getBlockTransData(rwWrites){
    let result = [];
    let writes = [];
    let jj = 0;
    for(let kk=0;kk<rwWrites.length;kk++){
        if(rwWrites[kk].rwset.writes.length>0){
            writes = rwWrites[kk].rwset.writes;
        }
    }
    for(let k=0;k<writes.length;k++){
    	//兼容老版数据取法
        if(writes[k].key.length === 64){
        	if(!value.after){
        		continue;
			}
            let value = JSON.parse(writes[k].value);
            let number = value.after.productId;
            let tx_id = writes[k].key;
            //老版时间是字符串改为秒
            let date = new Date(value.after.createTime);
            let time = date.getTime();//转换成秒
            result[jj++] = {
                "tx_id" : tx_id,
                "number" : number,
                "timestamp" : time
            };
        }
    	//升级版数据取法 统一取PRODUCT_INFO
        else if(writes[k].key.indexOf("PRODUCT_INFO") !== -1){
            let value = JSON.parse(writes[k].value);
            let number = value.productId;
            let tx_id = value.txId;
            let time = value.createTime;
            result[jj++] = {
                "tx_id" : tx_id,
                "number" : number,
                "timestamp" : time
            };
        }

    }
    return result;
}