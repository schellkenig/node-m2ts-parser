/*jslint node:true, nomen:true, plusplus:true, vars:true */
'use strict';

var util = require('util');
var fs   = require('fs');

var m2tsParser = require('..');

var pids = null;
if (process.argv[3]) {
	pids = process.argv[3].split(',');
	pids.forEach(function (pid, i) {
		
		pids[i] = parseInt(pid, 10);
	});
}
var reader = m2tsParser.createReader({
	pids: pids
});

var testStream = fs.createReadStream(process.argv[2]);

testStream.pipe(reader);

reader.on('data', function (packet) {
	
	util.puts('PID=' + packet.pid.toString(16) + '(' + (packet.type || '?') + ')');
	
	if (packet.payload) {
		var i, l;
		var s = '';
		for (i = 0, l = packet.payload.length; i < l; i++) {
			if (i !== 0 && i % 16 === 0) {
				s += '\n';
			}

			s += ('00' + packet.payload[i].toString(16)).slice(-2) + ' ';
		}
		s += '\n';
		
		util.puts(
			'payload=' + packet.payload.length,
			util.inspect(m2tsParser.parsePSI(packet.payload)),
			s
		);
	}
});