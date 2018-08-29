var bn = require('bn.js');
var Buffer = require('safe-buffer').Buffer;

function withPublic(paddedMsg, key) {
  return Buffer.from(paddedMsg
    .toRed(bn.mont(key.modulus))
    .redPow(new bn(key.publicExponent))
    .fromRed()
    .toArray());
}

module.exports = withPublic;
