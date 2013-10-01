/*jslint node:true, nomen:true, plusplus:true, vars:true */
'use strict';

var stream = require('stream');
var util   = require('util');

var parser = require('packet').createParser();
parser.packet('188', 'b32{x8, b1, b1, b1, b13, b2, b2, b4}, l1472');
//parser.packet('192', 'x32, b32{x8, b1, b1, b1, b13, b2, b2, b4}, l1504');

exports.define = {
	PID_TYPE: {
		0x0000: 'PAT',// Program Association Table
		0x0001: 'CAT',// Conditional Access Table
		0x0002: 'TSDT',// Transport Stream Description Table
		
		0x0010: 'NIT',// Network Information Table
		0x0011: 'SDT',// Service Description Table or BAT
		0x0012: 'EIT',// Event Information Table
		0x0013: 'RST',// Running Status Table
		0x0014: 'TOT',// Time Offset Table or TDT
		
		0x0017: 'DCT',// Download Control Table (ARIB STD-B16)
		
		0x001e: 'DIT',// Discontinuity Information Table (ARIB STD-B1, B21)
		0x001f: 'SIT',// Selection Information Table (ARIB STD-B1, B21)
		
		0x0020: 'LIT',// Local Event Information Table
		0x0021: 'ERT',// Event Relation Table
		0x0022: 'PCAT',// Partial Content Announcement Table
		0x0023: 'SDTT',// Software Download Trigger Table
		0x0024: 'SDTT',// Software Download Trigger Table
		0x0025: 'BIT',// Broadcaster Information Table
		0x0026: 'EIT',// Event Information Table
		0x0027: 'EIT',// Event Information Table
		0x0028: 'SDTT',// Software Download Trigger Table
		0x0029: 'CDT',// Common Data Table
		
		0x002f: 'MFHI',// Multi-Frame Header Information (JCTEA STD-002)
		
		0x1fc8: 'PMT',// Program Map Table
		0x1fc9: 'PMT',// Program Map Table
		
		0x1fff: 'NULL'
	}
};

// Usage:
// var reader = require('m2ts-parser').createReader();
// source.pipe(reader)
exports.Reader = function (opt) {
	if (!(this instanceof exports.Reader)) {
		return new exports.Reader(opt);
	}
	
	if (typeof opt === 'undefined') {
		opt = {};
	}
	
	stream.Transform.call(this, opt);
	this._writableState.objectMode = false;
	this._readableState.objectMode = true;
	
	this._bytes = null;
	
	var self = this;
	var pidTable  = {};
	var pids      = opt.pids || null;
	
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
		// drop error
		if (transport_error_indicator === 1) {
			return;
		}
		
		// pid filter
		if (pids !== null && pids.indexOf(pid) === -1) {
			return;
		}
		
		// 10 Adaptation_field only, no payload
		if (adaptation_field_control === 2) {
			self.push({
				pid             : pid,
				type            : exports.define.PID_TYPE[pid],
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
					type            : exports.define.PID_TYPE[pid],
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
			// PES or PSI
			if (body[0] === 0 && body[1] === 0 && body[2] === 1) {
				// trim packet_start_code_prefix (0x000001)
				pidTable[pid].payload = body.splice(3, body.length - 3);
			} else {
				// trim pointer_field
				pidTable[pid].payload = body.splice(1, body.length - 1);
			}
		} else {
			Array.prototype.push.apply(pidTable[pid].payload, body);
		}
	};//<-- this._transform_extractEntire()
};//<-- exports.Reader()

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