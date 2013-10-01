/*jslint node:true, nomen:true, plusplus:true, vars:true */
'use strict';

var fs = require('fs');

var m2tsParser = require('..');

var reader = m2tsParser.createReader();

var testStream = fs.createReadStream(__dirname + '/test3.m2ts');

testStream.pipe(reader);

reader.on('data', function (packet) {
	// PMTだけを出力
	if (packet.pid === 0x01f0) {
		console.log(JSON.stringify(packet));
	}
});