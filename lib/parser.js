/*jslint node:true, nomen:true, plusplus:true, vars:true */
'use strict';

var stream = require('stream');
var util   = require('util');

var parser = require('packet').createParser();
parser.packet('188', 'b32{x8, b1, b1, b1, b13, b2, b2, b4}, l1472');
//parser.packet('192', 'x32, b32{x8, b1, b1, b1, b13, b2, b2, b4}, l1504');

// Usage:
// var reader = new require('m2ts-parser').Reader();
// source.pipe(reader)

exports.Reader = function (opt) {
	if (!(this instanceof exports.Reader)) {
		return new exports.Reader(opt);
	}
	
	//opt.objectMode = true;
	
	stream.Transform.call(this, opt);
	this._writableState.objectMode = false;
	this._readableState.objectMode = true;
	
	this._bytes = null;
	
	var self = this;
	
	var pidTable = {};
	
	this._transform_extractEntire = function (
		transport_error_indicator,
		payload_unit_start_indicator,
		transport_priority,
		pid,
		transport_scrambling_control,
		adaptation_field_control,
		continuity_counter,
		body
	) {
		if (transport_error_indicator === 1) {
			return;
		}
		
		// pid filter here
		// ...
		
		// 10 Adaptation_field only, no payload
		if (adaptation_field_control === 2) {
			self.push({
				pid             : pid,
				adaptation_field: body
			});
			
			return;
		}
		
		//if (typeof pidTable[pid] !== 'undefined') {
		//	// continuity check here
		//	// ...
		//}
		
		if (payload_unit_start_indicator === 1) {
			if (typeof pidTable[pid] === 'undefined') {
				pidTable[pid] = {
					_continuity_counter: continuity_counter
				};
			} else {
				self.push({
					pid             : pid,
					adaptation_field: pidTable[pid].adaptation_field,
					payload         : pidTable[pid].payload
				});
				
				delete pidTable[pid].adaptation_field;
				delete pidTable[pid].payload;
			}
		}
		
		if (typeof pidTable[pid] === 'undefined') {
			return;
		}
		
		// 11 Adaptation_field followed by payload
		if (adaptation_field_control === 3) {
			if (payload_unit_start_indicator === 1) {
				pidTable[pid].adaptation_field = body.splice(0, body[0] + 1);
			} else {
				body.splice(0, body[0] + 1);
			}
		}
		
		if (payload_unit_start_indicator === 1) {
			// 11 Adaptation_field followed by payload
			if (adaptation_field_control === 3) {
				pidTable[pid].adaptation_field = body.splice(0, body[0] + 1);
			}
			
			// PES or PSI
			if (body[0] === 0 && body[1] === 0 && body[2] === 1) {
				// trim packet_start_code_prefix (0x000001)
				pidTable[pid].payload = body.splice(3, body.length - 3);
			} else {
				// trim pointer_field
				pidTable[pid].payload = body.splice(1, body.length - 1);
			}
		} else {
			//pidTable[pid].payload = pidTable[pid].payload.concat(body);
			Array.prototype.push.apply(pidTable[pid].payload, body);
		}
	};
};

util.inherits(exports.Reader, stream.Transform);

exports.createReader = function (opt) {
	return new exports.Reader(opt);
};

exports.Reader.prototype._transform = function (chunk, encoding, done) {
	var i, l;
	for (i = 0, l = chunk.length; i < l; i++) {
		// sync byte (0x47)
		if (chunk[i] === 71 && (this._bytes === null || this._bytes.length === 188)) {
			if (this._bytes !== null) {
				parser.extract('188', this._transform_extractEntire);
				parser.parse(this._bytes);
			}
			
			this._bytes = [];
		}
		
		if (this._bytes !== null) {
			this._bytes.push(chunk[i]);
		}
	}
	
	done();
};