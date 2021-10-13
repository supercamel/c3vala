/**
(c) 2016 Samuel Cowen <samuel.cowen89@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * C3 is a protocol & software library for coms between devices.
 * This file is a part of the C3 API
 * (c) 2016 Samuel Cowen <samuel.cowen89@gmail.com>
 */

'use strict';

const Binary = require('./binary');

module.exports = class C3 {
	constructor () {
		this.binary = new Binary();
		this.timeout = 100;

		this.MSG_STATE = {
			START_1: -1,
			START_2: 0,
			SYN: 1,
			ID_1: 2,
			ID_2: 3,
			SIZE: 4,
			DATA: 5,
			CHECK_1: 6,
			CHECK_2: 7
		};

		this.packets = [];
		this.enums = [];
		this.callbacks = [];
		this.list = []; //outbound packets to be sent / acked
		this.data_buf = [];
		this.sync = 0;
		this.state = this.MSG_STATE.START_1;
		this.data_pos = 0;
		this.data_length = 0;
		this.in_syn = 0;
		this.checksum_in = 0;
		this.packet_count = 0;
		this.coms_clear_cb = function () { };
	}
	// returns a fletcher16 checksum for the given buffer
	makeChecksum (buf, p) {
		var sum1 = 0xff;
		var sum2 = 0xff;
		var i = 0;
		var len = buf.length;

		while (len) {
			var tlen = len > 20 ? 20 : len;
			len -= tlen;
			do {
				sum2 += sum1 += buf[i++];
			} while (--tlen);
			sum1 = (sum1 & 0xff) + (sum1 >> 8);
			sum2 = (sum2 & 0xff) + (sum2 >> 8);
		}
		/* Second reduction step to reduce sums to 8 bits */
		sum1 = (sum1 & 0xff) + (sum1 >> 8);
		sum2 = (sum2 & 0xff) + (sum2 >> 8);
		return sum2 << 8 | sum1;
	}

	lookupEnumVal(name) {
		for(let i in this.enums) {
			let en = this.enums[i];
			for(let j in en.fields) {
				let enum_field = en.fields[j];
				let n = en.title + "_" + enum_field;
				if(name === n) {
					return j;
				}
			}
		}
		console.log("ERROR c3 couldn't find enum " + name);
		return -1;
	}

	createPacket (name, fields) {
		var pack = {};
		pack.name = name;
		pack.data = [];
		pack.sync = this.sync++;
		pack.data = pack.data.concat([pack.sync]);
		if (this.sync > 255) {
			this.sync = 0;
		}

		pack.id = -1;
		var s;

		for (var p in this.packets) {
			if (this.packets[p].title === name) {
				pack.id = this.packets[p].id;
				s = this.packets[p];
				break;
			}
		}

		if (pack.id === -1) {
			var err = {
				msg: 'Couldn\'t find packet ' + name
			};
			throw err;
		}

		pack.data = pack.data.concat(this.binary.uint16ToBytes(pack.id));
		pack.data.push(0); // placeholder for size

		var loops = 0;
		if(fields !== undefined) {
			loops = fields.length;
		}

		if (s.fields.length !== loops) {
			err = {
				msg: 'Invalid number of fields for this message type'
			};
			throw err;
		}

		for (var count = 0; count !== loops; count++) {
			var property = s.fields[count];
			if (property.type === 'uint32_t') {
				pack.data = pack.data.concat(this.binary.uint32ToBytes(parseInt(fields[count])));
			} else if (property.type === 'int32_t') {
				pack.data = pack.data.concat(this.binary.int32ToBytes(parseInt(fields[count])));
			} else if (property.type === 'float') {
				pack.data = pack.data.concat(this.binary.floatToBytes(parseFloat(fields[count])));
			} else if (property.type === 'uint16_t') {
				pack.data = pack.data.concat(this.binary.uint16ToBytes(parseInt(fields[count])));
			} else if (property.type === 'int16_t') {
				pack.data = pack.data.concat(this.binary.int16ToBytes(parseInt(fields[count])));
			} else if (property.type === 'uint8_t') {
				pack.data = pack.data.concat([parseInt(fields[count])]);
			} else if (property.type === 'int8_t') {
				pack.data = pack.data.concat([parseInt(fields[count])]);
			} else if (property.type.substring(0, 17) === 'etk::StaticString') {
				var lenStr = property.type.substring(18);
				lenStr = lenStr.substring(0, lenStr.length - 1);
				var len = parseInt(lenStr);
				var byteArray = [];
				for (var i = 0; i < len; i++) {
					byteArray.push(fields[count].charCodeAt(i));
				}
				pack.data = pack.data.concat(byteArray);
			} else if (property.type.substring(0, 17) === 'etk::List<uint8_t') {
				var sz = fields[count].length;
				pack.data.push(sz);
				for (i = 0; i < sz; i++) {
					pack.data.push(fields[count][i]);
				}
			} else {
				pack.data = pack.data.concat([parseInt(fields[count])]);
			}
		}

		pack.data[3] = pack.data.length - 4;
		pack.data = pack.data.concat(this.binary.uint16ToBytes(this.makeChecksum(pack.data)));
		this.list.push(pack);
	}

	serialise (sf) {
		this.list.forEach(function (pack, index) {
			if(pack.send_count === undefined) {
				pack.send_count = -1;
			}
			pack.send_count++;

			if((pack.send_count%20) === 0) {

				var d = [0xAB, 0xCD];
				d = d.concat(pack.data);
				sf(d);

				if (pack.id === 0) {
					this.list.splice(index, 1);
				} else if (this.packets[pack.id - 1].ack_required === 'false') {
					this.list.splice(index, 1);
				}
			}
			if(pack.send_count > this.timeout) {
				this.list.splice(index, 1);
				if(typeof this.timeout_cb === 'function') {
					this.timeout_cb(pack);
				}
			}
		}, this);
	}

	setTimeoutVal(timeout) {
		this.timeout = timeout;
	}

	onTimeout(timeout_cb) {
		this.timeout_cb = timeout_cb;
	}

	setStructInfo (contents) {
		this.packets = contents.packets;
		this.enums = contents.enums;

		var count = 1;
		for (var packet in this.packets) {
			this.packets[packet].id = count++;
		}
	}

	addCallback (packet, cb) {
		this.callbacks = this.callbacks.filter(function (element) {
			if (element.name === packet) {
				console.log('removing a duplicate callback for ' + packet);
			}
			return element.name !== packet;
		});
		this.callbacks.push({
			name: packet,
			callback: cb
		});
	}

	read (c) {
		switch (this.state) {
			case this.MSG_STATE.START_1:
				this.data_buf = [];

				if (c === 0xAB) {
					this.state++;
				}
				break;
			case this.MSG_STATE.START_2:
				if (c === 0xCD) {
					this.state++;
				} else {
					this.state = this.MSG_STATE.START_1;
				}
				break;
			case this.MSG_STATE.SYN:
				this.in_syn = c;
				this.data_buf.push(c);
				this.state++;
				break;
			case this.MSG_STATE.ID_1:
				this.msg_id = c;
				this.data_buf.push(c);
				this.state++;
				break;
			case this.MSG_STATE.ID_2:
				this.msg_id += (c << 8);
				this.data_buf.push(c);
				if (this.msg_id > this.packets.length) {
					this.state = this.MSG_STATE.START_1;
				} else {
					this.state++;
				}
				break;
			case this.MSG_STATE.SIZE:
				this.data_length = c;
				this.data_buf.push(c);
				this.state++;
				break;
			case this.MSG_STATE.DATA:
				this.data_buf.push(c);
				if (this.data_buf.length >= (this.data_length + 4)) {
					this.state++;
				}
				break;
			case this.MSG_STATE.CHECK_1:
				this.checksum_in = c;
				this.state++;
				break;
			case this.MSG_STATE.CHECK_2:
				this.checksum_in += (c << 8);

				var cs = this.makeChecksum(this.data_buf);

				if (cs === this.checksum_in) {
					this.readData();
				}

				this.state = this.MSG_STATE.START_1;
				break;
			default:
				this.state = this.MSG_STATE.START_1;
		}
	}

	readData () {
		var packet = {};

		this.packet_count += 1;
		// got an ack pack
		if (this.msg_id === 0) {
			var id = this.binary.bytesToUint16(this.data_buf, 4);
			var sync = this.data_buf[6];
			for (let i in this.list) {
				var outMsg = this.list[i];
				if ((outMsg.id === id) && (outMsg.sync === sync)) {
					this.list.splice(i, 1);
					if(this.list.length === 0) {
						if(typeof coms_clear_cb === "function") {
							coms_clear_cb();
						}
					}
				}
			}

			return;
		}

		var pack = this.packets[this.msg_id - 1];
		if (pack === undefined) {
			return;
		}

		var pos = 4;
		for (let i in pack.fields) {
			var field = pack.fields[i];
			if (field.type === 'int8_t') {
				packet[field.name] = this.data_buf[pos++] - 128;
			} else if (field.type === 'uint8_t') {
				packet[field.name] = this.data_buf[pos++];
			} else if (field.type === 'int16_t') {
				packet[field.name] = this.binary.bytesToInt16(this.data_buf, pos);
				pos += 2;
			} else if (field.type === 'uint16_t') {
				packet[field.name] = this.binary.bytesToUint16(this.data_buf, pos);
				pos += 2;
			} else if (field.type === 'int32_t') {
				packet[field.name] = this.binary.bytesToInt32(this.data_buf, pos);
				pos += 4;
			} else if (field.type === 'uint32_t') {
				packet[field.name] = this.binary.bytesToInt32(this.data_buf, pos);
				pos += 4;
			} else if (field.type === 'float') {
				packet[field.name] = this.binary.bytesToFloat(this.data_buf, pos);
				pos += 4;
			} else if (field.type.substring(0, 17) === 'etk::StaticString') {
				var lenStr = field.type.substring(18);
				lenStr = lenStr.substring(0, lenStr.length - 1);
				let sz = parseInt(lenStr);
				var str = this.data_buf(pos, pos + sz);
				packet[field.name] = String.fromCharCode.apply(String, str);
				pos += sz;
			} else if (field.type.substring(0, 17) === 'etk::List<uint8_t') {
				let sz = this.data_buf[pos++];
				packet[field.name] = [];
				for (let i = 0; i < sz; i++) {
					packet[field.name].push(this.data_buf[pos++]);
				}
			} else {
				packet[field.name] = this.data_buf[pos++];
			}
		}

		if (pack.ack_required === 'true') {
			var ackPack = {};
			ackPack.data = [];
			ackPack.sync = this.sync++;
			ackPack.ack_required = false;
			ackPack.data = ackPack.data.concat([ackPack.sync]);
			ackPack.data = ackPack.data.concat(this.binary.uint16ToBytes(0));
			ackPack.data = ackPack.data.concat([3]);
			ackPack.data = ackPack.data.concat(this.binary.uint16ToBytes(this.msg_id));
			ackPack.id = 0;

			ackPack.data = ackPack.data.concat([this.in_syn]);
			if (this.sync > 255) {
				this.sync = 0;
			}
			ackPack.data = ackPack.data.concat(this.binary.uint16ToBytes(this.makeChecksum(ackPack.data)));
			this.list.push(ackPack);
		}

		for (var n in this.callbacks) {
			if (this.callbacks[n].name === pack.title) {
				this.callbacks[n].callback(packet);
				break;
			}
		}
	}
};
