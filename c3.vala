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
        uint data_buf[256];
        uint8 sync;
        uint timeout;

        Json.Array enums;
        Json.Array packets;

        Gee.ArrayList<Packet?> outbound;


        public Parser() {
            MsgState state = MsgState.START1;
            data_pos = 0;
            outbound = new Gee.ArrayList<Packet>();
            timeout = 10;
        }

        public void load_json(string path) {
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
            parser.load_from_data ((string)buf , -1);

            var root_object = parser.get_root().get_object ();
            enums = root_object.get_array_member("enums");
            packets = root_object.get_array_member("packets");
        }

        // returns a fletcher16 checksum for the given buffer
        public uint16 make_checksum(uint8* buf, uint len) {
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
        }

        /**
         * Returns a numeric value from an enum member name
         */
        public int lookup_enum_value(string name) {
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
        }

        public int lookup_packet_num_from_name(string name) {
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
        }

        public Json.Object? lookup_packet_from_name(string name) {
            foreach(var pack in packets.get_elements()) {
                var nodeobj = pack.get_object();
                if(nodeobj.get_string_member("title") == name) {
                    return nodeobj;
                }
            }
            return null;
        }

        public void create_packet(string name, Gee.HashMap<string, Value?> elements) {
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
                if(element_name in elements) {
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
                        var len = lenstr.to_int();
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

        public Gee.ArrayList<uint8> serialise() {
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
        }
    }
}


int main() {
    var c3 = new c3.Parser();
    c3.load_json("../apx.json");

    var map = new Gee.HashMap<string, Value?>();
    var val = Value(typeof(float));
    val.set_float(100.0f);
    map.set("target_alt", val);
    c3.create_packet("set_target_altitude", map);

    var bytes = c3.serialise();
    foreach(var byte in bytes) {
        print(byte.to_string() + " ");
    }

    return 0;
}


