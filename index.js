var crypto = require('crypto');
if (typeof crypto.publicEncrypt !== 'function') {
  crypto = require('./browser');
}
exports.publicEncrypt = crypto.publicEncrypt;
exports.privateDecrypt = crypto.privateDecrypt;