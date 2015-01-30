var test = require('tape');
var fs = require('fs');
var constants = require('constants');
var parseKeys = require('parse-asn1');
var priv1024 = fs.readFileSync(__dirname + '/rsa.1024.priv');
var rsa1024 = {
	private: fs.readFileSync(__dirname + '/rsa.1024.priv'),
	public: fs.readFileSync(__dirname + '/rsa.1024.pub')
};
var rsa1024priv = {
	private: fs.readFileSync(__dirname + '/rsa.1024.priv'),
	public: fs.readFileSync(__dirname + '/rsa.1024.priv')
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
var pass2028 = {
	private: {
		passphrase: 'password',
		key:fs.readFileSync(__dirname + '/rsa.pass.priv')
	},
	public: fs.readFileSync(__dirname + '/rsa.pass.pub')
};

var nodeCrypto = require('../');
var myCrypto = require('../browser');
function _testIt(keys, message, t) {
	var pub = keys.public;
	var priv = keys.private;
	t.test(message.toString(), function (t) {
		t.plan(4);

		var myEnc = myCrypto.publicEncrypt(pub, message);
		var nodeEnc = nodeCrypto.publicEncrypt(pub, message);
		t.equals(myCrypto.privateDecrypt(priv, myEnc).toString('hex'), message.toString('hex'), 'my decrypter my message');
		t.equals(myCrypto.privateDecrypt(priv, nodeEnc).toString('hex'), message.toString('hex'), 'my decrypter node\'s message');
		t.equals(nodeCrypto.privateDecrypt(priv, myEnc).toString('hex'), message.toString('hex'), 'node decrypter my message');
		t.equals(nodeCrypto.privateDecrypt(priv, nodeEnc).toString('hex'), message.toString('hex'), 'node decrypter node\'s message');
	});
}
function testIt(keys, message, t) {
	_testIt(keys, message, t);
	_testIt(paddingObject(keys, 1), Buffer.concat([message, new Buffer(' with RSA_PKCS1_PADDING')]), t);
	var parsedKey = parseKeys(keys.public);
	var k = parsedKey.modulus.byteLength();
	var zBuf = new Buffer(k);
	zBuf.fill(0);
	var msg = Buffer.concat([zBuf, message, new Buffer(' with no padding')]).slice(-k);
	_testIt(paddingObject(keys, 3), msg, t);
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
function testRun(i) {
	test('run ' + i, function (t) {
		testIt(rsa1024priv, new Buffer('1024 2 private keys'), t);
		testIt(rsa1024, new Buffer('1024 keys'), t);
		testIt(rsa2028, new Buffer('2028 keys'), t);
		testIt(nonrsa1024, new Buffer('1024 keys non-rsa key'), t);
		testIt(pass1024, new Buffer('1024 keys and password'), t);
		testIt(nonrsa1024str, new Buffer('1024 keys non-rsa key as a string'), t);
		testIt(pass2028, new Buffer('2028 rsa key with variant passwords'), t);
	});
}


// Test RSA encryption/decryption
test('node tests', function (t) {
	var certPem = fs.readFileSync(__dirname + '/test_cert.pem', 'ascii');
	var keyPem = fs.readFileSync(__dirname + '/test_key.pem', 'ascii');
	var rsaPubPem = fs.readFileSync(__dirname + '/test_rsa_pubkey.pem',
	    'ascii');
	var rsaKeyPem = fs.readFileSync(__dirname + '/test_rsa_privkey.pem',
	    'ascii');
	var rsaKeyPemEncrypted = fs.readFileSync(
  __dirname + '/test_rsa_privkey_encrypted.pem', 'ascii');
  var input = 'I AM THE WALRUS';
  var bufferToEncrypt = new Buffer(input);

  var encryptedBuffer = myCrypto.publicEncrypt(rsaPubPem, bufferToEncrypt);

  var decryptedBuffer = myCrypto.privateDecrypt(rsaKeyPem, encryptedBuffer);
  t.equal(input, decryptedBuffer.toString());

  var decryptedBufferWithPassword = myCrypto.privateDecrypt({
    key: rsaKeyPemEncrypted,
    passphrase: 'password'
  }, encryptedBuffer);
  t.equal(input, decryptedBufferWithPassword.toString());

  // encryptedBuffer = myCrypto.publicEncrypt(certPem, bufferToEncrypt);

  // decryptedBuffer = myCrypto.privateDecrypt(keyPem, encryptedBuffer);
  // t.equal(input, decryptedBuffer.toString());

  encryptedBuffer = myCrypto.publicEncrypt(keyPem, bufferToEncrypt);

  decryptedBuffer = myCrypto.privateDecrypt(keyPem, encryptedBuffer);
  t.equal(input, decryptedBuffer.toString());

  encryptedBuffer = myCrypto.privateEncrypt(keyPem, bufferToEncrypt);

  decryptedBuffer = myCrypto.publicDecrypt(keyPem, encryptedBuffer);
  t.equal(input, decryptedBuffer.toString());

  t.throws(function() {
    myCrypto.privateDecrypt({
      key: rsaKeyPemEncrypted,
      passphrase: 'wrong'
    }, encryptedBuffer);
  });
  t.end();
});

var i = 0;
var num = 20;
while (++i <= 20) {
	testRun(i);
}
