var sc = require('js-scrypt');
var crypto = require('crypto');

exports.hashSCrypt = function hashSCrypt(input, salt, cb) {
	sc.hash(input, salt, function(err, result){
		cb(err, result && result.toString('base64'));
	});
}

exports.hashSha512 = function hashSha512(input, salt, cb) {
	setImmediate(function(){
		var hash = crypto.createHash('sha512')
		hash.write(new Buffer(input || '','utf8'));
		hash.write(new Buffer(saltBase64 || '', 'utf8'));
		cb(null, hash.digest('base64'));
	});
}
