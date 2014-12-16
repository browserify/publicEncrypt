var test = require('tape');
var fs = require('fs');
var constants = require('constants');
var parseKeys = require('parse-asn1');
var priv1024 = fs.readFileSync(__dirname + '/rsa.1024.priv');
var rsa1024 = {
	private: fs.readFileSync(__dirname + '/rsa.1024.priv'),
	public: fs.readFileSync(__dirname + '/rsa.1024.pub')
};
var rsa1024 = {
	private: fs.readFileSync(__dirname + '/rsa.1024.priv'),
	public: fs.readFileSync(__dirname + '/rsa.1024.pub')
};
var rsa2028 = {
	private: fs.readFileSync(__dirname + '/rsa.2028.priv'),
	public: fs.readFileSync(__dirname + '/rsa.2028.pub')
};
var nonrsa1024 = {
	private: fs.readFileSync(__dirname + '/1024.priv'),
	public: fs.readFileSync(__dirname + '/1024.pub')
};
var nonrsa1024str = {
	private: fs.readFileSync(__dirname + '/1024.priv').toString(),
	public: fs.readFileSync(__dirname + '/1024.pub').toString()
};
var pass1024 = {
	private: {
		passphrase: 'fooo',
		key:fs.readFileSync(__dirname + '/pass.1024.priv')
	},
	public: fs.readFileSync(__dirname + '/pass.1024.pub')
};

var nodeCrypto = require('crypto');
var myCrypto = require('../');
function _testIt(keys, message) {
	var pub = keys.public;
	var priv = keys.private;
	test(message.toString(), function (t) {
		t.plan(4);
		var myEnc = myCrypto.publicEncrypt(pub, message);
		var nodeEnc = nodeCrypto.publicEncrypt(pub, message);
		t.equals(myCrypto.privateDecrypt(priv, myEnc).toString('hex'), message.toString('hex'), 'my decrypter my message');
		t.equals(myCrypto.privateDecrypt(priv, nodeEnc).toString('hex'), message.toString('hex'), 'my decrypter node\'s message');
		t.equals(nodeCrypto.privateDecrypt(priv, myEnc).toString('hex'), message.toString('hex'), 'node decrypter my message');
		t.equals(nodeCrypto.privateDecrypt(priv, nodeEnc).toString('hex'), message.toString('hex'), 'node decrypter node\'s message');
	});
}
function testIt(keys, message) {
	_testIt(keys, message);
	_testIt(paddingObject(keys, constants.RSA_PKCS1_PADDING), Buffer.concat([message, new Buffer(' with RSA_PKCS1_PADDING')]));
	var parsedKey = parseKeys(keys.public);
	var k = parsedKey.modulus.byteLength();
	var zBuf = new Buffer(k);
	zBuf.fill(0);
	var msg = Buffer.concat([zBuf, message, new Buffer(' with no padding')]).slice(-k);
	_testIt(paddingObject(keys, constants.RSA_NO_PADDING), msg);
}
function paddingObject(keys, padding) {
	return {
		public: addPadding(keys.public, padding),
		private: addPadding(keys.private, padding)
	};
}
function addPadding(key, padding) {
	if (typeof key === 'string' || Buffer.isBuffer(key)) {
		return {
			key: key,
			padding: padding
		};
	}
	var out = {
		key: key.key,
		padding:padding
	};
	if ('passphrase' in key) {
		out.passphrase = key.passphrase;
	}
	return out;
}
testIt(rsa1024, new Buffer('1024 keys'));
testIt(rsa2028, new Buffer('2028 keys'));
testIt(nonrsa1024, new Buffer('1024 keys non-rsa key'));
testIt(pass1024, new Buffer('1024 keys and password'));
testIt(nonrsa1024str, new Buffer('1024 keys non-rsa key as a string'));