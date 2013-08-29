var sc = require('./scrypt');
var crypto = require('crypto');

exports.hashSCrypt = function hashSCrypt(input, saltBase64) {
	var sc_i = sc.encode_utf8(input);
	var sc_s = sc.encode_utf8(new Buffer(saltBase64 || '', 'base64').toString('utf8'));
	var sc_hsh = sc.crypto_scrypt(sc_i, sc_s, 1024, 8, 1, 64);
	var sc_buf = new Buffer(sc_hsh.length);
	for (var i=0; i<sc_hsh.length; i++) sc_buf[i] = sc_hsh[i];
	return sc_buf.toString('base64');
}

exports.hashSha512 = function hashSha512(input, saltBase64) {
	var hash = crypto.createHash('sha512')
	hash.write(new Buffer(input,'utf8'));
	hash.write(new Buffer(saltBase64 || '', 'base64'));
	return hash.digest('base64');
}
