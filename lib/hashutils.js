var sc = require('./scrypt');
var crypto = require('crypto');

exports.HashSCrypt = function HashSCrypt(input, saltBase64) {
	var sc_i = sc.encode_utf8(input);
	var sc_s = sc.encode_utf8(new Buffer(saltBase64 || '', 'base64').toString('utf8'));
	var sc_ret = sc.crypto_scrypt(sc_i, sc_s, 1024, 8, 1, 64);
	var sc_merg = Array.prototype.map.call(sc_ret, function(x){ return String.fromCharCode(x); }).join('');
	var sc_buff = new Buffer(sc_merg, 'binary');
	return sc_buff.toString('base64');
}

exports.HashSha512 = function HashSha512(input, saltBase64) {
	var b1 = new Buffer(input,'utf8');
	var b2 = new Buffer(saltBase64 || '', 'base64');
	var bytes = Buffer.concat([b1, b2]);
	var hash = crypto.createHash('sha512')

	hash.write(b1);
	hash.write(b2);
	return hash.digest('base64');
}
