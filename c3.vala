namespace c3 {

	enum MsgState {
		START1,
		START2,
		SYN,
		ID1,
		ID2,
		SIZE,
		PAYLOAD,
		CHECK1,
		CHECK2
	}

	private struct Packet {
		public string name;
		public uint8 sync;
		public uint16 id;
		public uint8 data[256];
		public uint8 data_len;
		public uint send_count;
	}


	public class Parser {
		MsgState state;
		uint data_pos;
		uint data_length;
		uint bytes_read;
		uint8 data_buf[256];
		uint8 in_sync;
		uint8 sync;
		uint16 msg_id;
		uint timeout;
		uint8 checksum_in;

		Json.Array enums;//{{{
		Json.Array packets;

		Gee.ArrayList<Packet?> outbound;

		public signal void on_packet_recv(string name, Gee.HashMap<string, Value?> param);


		public Parser() {
			state = MsgState.START1;
			data_pos = 0;
			outbound = new Gee.ArrayList<Packet>();
			timeout = 10;
		}

		/**
		 * Loads the C3 JSON file.
		 */
		public void load_json(string path) {//{{{
			FileStream stream = FileStream.open(path, "r");
			if(stream == null) {
				print("C3 json file could not be opened.\n");
				return;
			}

			stream.seek (0, FileSeek.END);
			long size = stream.tell ();
			stream.rewind ();

			uint8[] buf = new uint8[size];
			size_t read = stream.read (buf, 1);

			var parser = new Json.Parser ();
			try {
				parser.load_from_data ((string)buf , -1);
				var root_object = parser.get_root().get_object ();
				enums = root_object.get_array_member("enums");
				packets = root_object.get_array_member("packets");

			}
			catch(GLib.Error err) {
				print("Error loading JSON file.\n");
			}
		}//}}}

		// returns a fletcher16 checksum for the given buffer
		public uint16 make_checksum(uint8* buf, uint len) {//{{{

			uint sum1 = 0xff;
			uint sum2 = 0xff;
			uint i = 0;

			while (len != 0) {
				var tlen = len > 20 ? 20 : len;
				len -= tlen;
				do {
					sum2 += sum1 += buf[i++];
				} while (--tlen != 0);
				sum1 = (sum1 & 0xff) + (sum1 >> 8);
				sum2 = (sum2 & 0xff) + (sum2 >> 8);
			}
			/* Second reduction step to reduce sums to 8 bits */
			sum1 = (sum1 & 0xff) + (sum1 >> 8);
			sum2 = (sum2 & 0xff) + (sum2 >> 8);
			return (uint16)(sum2 << 8 | sum1);
		}//}}}

		/**
		 * Returns a numeric value from an enum member name
		 */
		public int lookup_enum_value(string name) {//{{{
			foreach(var en in enums.get_elements()) {
				var nodeobj = en.get_object();
				var title = nodeobj.get_string_member("title");
				var fields = nodeobj.get_array_member("fields");
				int count = 0;
				foreach(var element in fields.get_elements()) {
					var n = title + "_" + element.get_string();
					if(n == name) {
						return count;
					}

					count++;
				}
			}

			return -1;
		}//}}}

		/**
		 * Returns the packet number from the title
		 */
		public int lookup_packet_num_from_name(string name) {//{{{
			int count = 0;
			foreach(var pack in packets.get_elements()) {
				var nodeobj = pack.get_object();
				var title = nodeobj.get_string_member("title");
				if(title == name) {
					return count;
				}
				count++;
			}

			return -1;
		}//}}}

		/**
		 * returns the JSON Object of a packet from the packet title
		 */
		public Json.Object? lookup_packet_from_name(string name) {//{{{
			foreach(var pack in packets.get_elements()) {
				var nodeobj = pack.get_object();
				if(nodeobj.get_string_member("title") == name) {
					return nodeobj;
				}
			}
			return null;
		}//}}}

		/**
		 * returns the JSON object of a packet by its ID. returns null on failure.
		 */
		public Json.Object? lookup_packet_from_id(uint16 id) {//{{{
			if(id >= packets.get_length()) {
				return null;
			}
			else {
				return packets.get_object_element(id);
			}
		}//}}}
		//}}}
		/**
		 * The read function is for byte-by-byte parsing of an input stream
		 */
		public void read(uint8 b) {//{{{
			switch(state) {
				case MsgState.START1:
					if(b == 0xAB) {
						state = MsgState.START2;
						data_pos = 0;
					}
					break;
				case MsgState.START2:
					if(b == 0xCD) {
						state = MsgState.SYN;
					}
					else {
						state = MsgState.START1;
					}
					break;
				case MsgState.SYN:
					in_sync = b;
					data_buf[0] = b;
					state = MsgState.ID1;
					break;
				case MsgState.ID1:
					data_buf[1] = b;
					msg_id = b;
					state = MsgState.ID2;
					break;
				case MsgState.ID2:
					data_buf[2] = b;
					msg_id += (b << 8);
					if(msg_id > packets.get_length()) {
						state = MsgState.START1;
					} 
					else {
						state = MsgState.SIZE;
					}
					break;
				case MsgState.SIZE:
					data_length = b;
					data_buf[3] = b;
					state = MsgState.PAYLOAD;
					bytes_read = 4;
					break;
				case MsgState.PAYLOAD:
					data_buf[bytes_read++] = b;
					if(bytes_read >= (data_length+4)) {
						state = MsgState.CHECK1;
					}
					break;
				case MsgState.CHECK1:
					checksum_in = b;
					state = MsgState.CHECK2;
					break;
				case MsgState.CHECK2:
					uint8 cs_parts[2];
					cs_parts[0] = checksum_in;
					cs_parts[1] = b;

					uint16 checksum = *(uint16*)(cs_parts);

					var cs = make_checksum(data_buf, bytes_read);

					if(checksum == cs) {
						deserialise();
					}
					state = MsgState.START1;
					break;
			}
		}//}}}

		private void deserialise() {//{{{
			var packet = Packet();

			// received an ACK packet
			if(msg_id == 0) {
				process_ack();
			}
			// receive normal packets
			else {
				var pos = 4;
				var map = new Gee.HashMap<string, Value?>();
				/*
				   var val = Value(typeof(float));
				   val.set_float(100.0f);
				   map.set("target_alt", val);
				   */

				var jsonobj = lookup_packet_from_id(msg_id);
				if(jsonobj != null) {
					var fields = jsonobj.get_array_member("fields");	
					foreach(var field in fields.get_elements()) {//{{{
						var field_object = field.get_object();
						var type = field_object.get_string_member("type");
						if(type == "uint8_t") {
							var val = Value(typeof(uint));
							val.set_uint((uint)data_buf[pos++]);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "uint16_t") {
							var val = Value(typeof(uint));
							uint16 d = *(uint16*)(&data_buf[pos]);
							pos += 2;
							val.set_uint(d);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "uint32_t") {
							var val = Value(typeof(uint));
							uint16 d = *(uint16*)(&data_buf[pos]);
							pos += 4;
							val.set_uint(d);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "int8_t") {
							var val = Value(typeof(int));
							val.set_int((int)data_buf[pos++]);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "int16_t") {
							var val = Value(typeof(int));
							int16 d = *(int16*)(&data_buf[pos]);
							pos += 2;
							val.set_int(d);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "int32_t") {
							var val = Value(typeof(int));
							int32 d = *(int32*)(&data_buf[pos]);
							pos += 4;
							val.set_int(d);
							map.set(field_object.get_string_member("name"), val);
						}
						else if(type == "float") {
							var val = Value(typeof(float));
							val.set_float(*(float*)(&data_buf[pos]));
							pos += 4;
							map.set(field_object.get_string_member("name"), val);
						}
						else {
							print("Packet received has unsupported type " + type + "\n");
						}
						//}}}

					}

					on_packet_recv(jsonobj.get_string_member("title"), map);
				}
			}
		}//}}}

		private void process_ack() {//{{{
			uint16 ack_id = *(uint16*)(&data_buf[4]);	
			uint sync = data_buf[6];
			foreach(var p in outbound) {
				// if the ack'd id and sync matches one of the outbound packets, 
				// then it has been received and must be removed from the outbound list
				if((p.id == ack_id) && (p.sync == sync)) {
					outbound.remove(p);
				}
			}
		}//}}}

		/**
		 * Creates the packet and adds it to the outbound queue
		 */
		public void create_packet(string name, Gee.HashMap<string, Value?> elements) {//{{{
			var pack = Packet();
			pack.data_len = 4;
			pack.sync = sync++;
			pack.data[0] = pack.sync;
			pack.send_count = 0;

			var id = lookup_packet_num_from_name(name);
			if(id == -1) {
				print("Packet name " + name + " not found in json file\n");
				return;
			}

			pack.id = (uint16)id;
			uint8* pid = (uint8*)&pack.id;
			pack.data[1] = pid[0];
			pack.data[2] = pid[1];

			var packet_object = lookup_packet_from_name(name);
			var fieldsobj = packet_object.get_array_member("fields");

			var n_fields = elements.size;
			if(n_fields != fieldsobj.get_length()) {
				print("Wrong number of fields passed for packet " + name + "\n");
				print("Msg not sent\n");
				return;
			}

			foreach(var field in fieldsobj.get_elements()) {
				var element_object = field.get_object();
				var element_name = element_object.get_string_member("name");
				if(elements.has_key(element_name)) {
					var element = elements.get(element_name);
					var type = element_object.get_string_member("type");
					if(type == "uint8_t") {
						pack.data[pack.data_len++] = (uint8)element.get_uint();
					}
					if(type == "int8_t") {
						pack.data[pack.data_len++] = (uint8)element.get_int();
					}
					if(type == "uint16_t") {
						var u = element.get_uint();
						uint8* pi = (uint8*)&u;
						pack.data[pack.data_len++] = pi[0];
						pack.data[pack.data_len++] = pi[1];
					}
					if(type == "int16_t") {
						var u = element.get_int();
						uint8* pi = (uint8*)&u;
						pack.data[pack.data_len++] = pi[0];
						pack.data[pack.data_len++] = pi[1];
					}
					if(type == "uint32_t") {
						var u = element.get_uint();
						uint8* pi = (uint8*)&u;
						for(int i = 0; i < 4; i++) {
							pack.data[pack.data_len++] = pi[i];
						}
					}
					if(type == "int32_t") {
						var u = element.get_int();
						uint8* pi = (uint8*)&u;
						for(int i = 0; i < 4; i++) {
							pack.data[pack.data_len++] = pi[i];
						}
					} 
					if(type == "float") {
						var u = element.get_float();
						uint8* pi = (uint8*)&u;
						for(int i = 0; i < 4; i++) {
							pack.data[pack.data_len++] = pi[i];
						}
					}
					if(type.has_prefix("etk::StaticString")) {
						var lenstr = type.substring(18, 3);
						var len = int.parse(lenstr);
						var str = element.get_string();
						for(int i = 0; i < len; i++) {
							pack.data[pack.data_len++] = str.@get(i);
						}
					}
				}

				else {
					print("Missing field " + element_name + " while sending packet " + name + "\n");
				}

				pack.data[3] = pack.data_len - 4;
			}

			var cs = make_checksum(pack.data, pack.data_len);
			pid = (uint8*)&cs;
			pack.data[pack.data_len++] = pid[0];
			pack.data[pack.data_len++] = pid[1];

			outbound.add(pack);
		}
		//}}}
		/**
		 * Convert the outbound queue into an array of bytes to send
		 */
		public Gee.ArrayList<uint8> serialise() {//{{{
			var ret = new Gee.ArrayList<uint8>();
			foreach(var packet in outbound) {
				if((packet.send_count%20) == 0) {
					ret.add(0xAB);
					ret.add(0xCD);

					for(var i = 0; i < packet.data_len; i++) {
						ret.add(packet.data[i]);
					}
				}

				if(packet.send_count > timeout) {
					// TODO create timeout signal
					outbound.remove(packet);
				}

				packet.send_count++;
			}
			return ret;
		}//}}}
	}
}


int main() {
	var c3 = new c3.Parser();
	c3.load_json("../apx.json");

	c3.on_packet_recv.connect((name, map) => {
		print("received " + name + "\n");

		if(name == "set_target_altitude") {
			float alt = map.get("target_alt").get_float();
			print(alt.to_string() + "\n");
		}
	});

	var map = new Gee.HashMap<string, Value?>();
	var val = Value(typeof(float));
	val.set_float(100.8f);
	map.set("target_alt", val);

	c3.create_packet("set_target_altitude", map);

	var bytes = c3.serialise();
	foreach(var byte in bytes) {
		c3.read(byte);
	}

	return 0;
}


