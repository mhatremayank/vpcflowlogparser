from vpcflowlogparser.protocol_mapper.protocol_number_mapper import ProtocolMapper as PM

# Author: Mayank
# Date: 10/11/2024

class FlowLogParser(object):
    def __init__(self, flowlog_file=None, lookuptable_file=None):
        if flowlog_file is None:
            self.flowlog_file = "vpcflowlogparser/flow_datastore/flowlogs_v2.txt"
        if lookuptable_file is None:
            self.lookuptable_file = "vpcflowlogparser/lookup_table_store/lookup_table.txt"
    
    def parse_flowlog_file(self):
        """
        This method parses flow log into dictionary as follows and also refers to protocol conversion map and 
        replaces protocol number to protocol_string such as "tcp", "icmp", "bgp" etc
        flow_log_dict = {"version": 2,
         "account-id": 123456789012, 
         "interface-id": "eni-0a1b2c3d",
         "srcaddr": "10.0.1.201",
         "dstaddr": "198.51.100.2",
         "srcport": 443,
         "dstport": 49153,
         "protocol":6,
         "packets": 25,
         "bytes": 20000,
         "start": 1620140761,
         "end": 1620140821,
         "action": ACCEPT,
         "log-status": OK
         }
        It returns a list of dictionaries with all parsed values from the flowlog file
        """
        proto_mapper = PM()
        protocol_map = proto_mapper.parse_protocols()
        with open(self.flowlog_file,'r') as logfd:
            flow_records_dump = logfd.readlines()
        flow_log_dict_list = [] #This list will hold all the mappings of flow logs entries, every line of flow log represents one entry
        for flow_record_str in flow_records_dump:
            flow_record_str = flow_record_str.rstrip("\n").rstrip()
            flow_record = flow_record_str.split()
            flow_log_dict = {}
            version = flow_record[0]
            account_id = flow_record[1]
            interface_id = flow_record[2]
            srcaddr = flow_record[3]
            dstaddr = flow_record[4]
            srcport = flow_record[5]
            dstport = flow_record[6]
            protocol_num = flow_record[7]
            protocol = protocol_map[int(protocol_num)]
            packets = flow_record[8]
            sentbytes = flow_record[9]
            start = flow_record[10]
            end = flow_record[11]
            action = flow_record[12]
            log_status = flow_record[13]
            flow_log_dict["version"] = int(version)
            flow_log_dict["account-id"] = account_id
            flow_log_dict["interface-id"] = interface_id
            flow_log_dict["srcaddr"] = srcaddr
            flow_log_dict["dstaddr"] = dstaddr
            flow_log_dict["srcport"] = int(srcport)
            flow_log_dict["dstport"] = int(dstport)
            flow_log_dict["protocol"] = protocol
            flow_log_dict["packets"] = int(packets)
            flow_log_dict["bytes"] = int(sentbytes)
            flow_log_dict["star"] = int(start)
            flow_log_dict["end"] = int(end)
            flow_log_dict["action"] = action
            flow_log_dict["log_status"] = log_status
            flow_log_dict_list.append(flow_log_dict)
        return flow_log_dict_list
    
    def parse_lookuptable_file(self):
        """
        This method parses lookup table file located at "vpcflowlogparser/lookup_table_store/lookup_table.txt"
        Instead of keeping the value formatting as lookup table, this method creates a hashable tuple to parse and access
        data from the dictionary. Associated values are tags from the lookup table.
        Hashable tuple are acting as predetermined hash functions for faster O(1) lookups for huge lookuptable data
        It provides optimization over O(n) map iteration and search for basic key, val dictionary

        This method returns a dictionary in following format: { ('25', 'tcp'): ['sv_p1'], ('68', 'udp'): ['sv_p2']}
        Note that tags are being maintained in a list even though a single element for conflicting corner cases where multiple tags are associated
        with the same tuple
        """
        with open(self.lookuptable_file, 'r') as loglt:
            ltdump = loglt.readlines()
        # lookup_table_dict_list = []
        lookup_entry_dict = {}
        header = ltdump[0]
        header = header.rstrip("\n").rstrip()
        header_list = header.split(",")
        ltdump.pop(0)
        for entry in ltdump:
            entry = entry.rstrip("\n").rstrip()
            entry_list = entry.split(",")
            dstport = int(entry_list[0])
            protocol = entry_list[1]
            tuple_hash = (dstport,protocol)
            if tuple_hash not in lookup_entry_dict:
                lookup_entry_dict[tuple_hash] = [entry_list[2].lower()]
            else:
                #case where lookuptable has same dstport, protocol associated to more than one tag
                lookup_entry_dict[tuple_hash].append(entry_list[2].lower())
        return lookup_entry_dict
    
        
    def flow_tag_count_logger(self):
        """
        This method analyzes and creates a counter map for two things:
        1. Tag occurences in flow log file, where tags are derived from lookup table
        2. Port/Protocol combo occrences in flow log file. 
        We are leveraging parse_lookuptable_file method output to achieve both of these things

        This method returns two maps in the following format:
        {'untagged': 8, 'sv_p2': 1, 'sv_p1': 2, 'email': 7}
        {(49153, 'tcp'): 1, (49154, 'tcp'): 1, (49155, 'tcp'): 1}
        """
        tag_counter = {}
        port_proto_combo_counter = {}
        tag_counter['untagged'] = 0
        flow_log_dict_list = self.parse_flowlog_file()
        lookuptable_seed_data = self.parse_lookuptable_file()
        for flow_log_entry in flow_log_dict_list:
            hash_tuple = (flow_log_entry['dstport'],flow_log_entry['protocol'])
            if hash_tuple not in port_proto_combo_counter:
                port_proto_combo_counter[hash_tuple] = 1
            else:
                port_proto_combo_counter[hash_tuple] += 1
            if hash_tuple in lookuptable_seed_data:
                tag = lookuptable_seed_data[hash_tuple]
                for i in tag:
                    if i not in tag_counter:
                        tag_counter[i] = 1
                    else:
                        tag_counter[i] += 1
            else:
                tag_counter['untagged'] += 1
        
        return tag_counter, port_proto_combo_counter

    def data_logger(self):
        """
        This method acquires processed data from the previous method flow_tag_count_logger()
        and simply writes to the file.
        Note that every call will overwrite previously written data.
        If append functionality is needed we can easily change the file-handling mode from "w" to "a+"
        """
        tag_counter, port_proto_combo_counter = self.flow_tag_count_logger()
        with open("vpcflowlogparser/flow_data_parser/tag_count.log", "w+") as tag_counter_log_file:
            tag_counter_log_file.write("tag,count"+"\n")
            for tag, count in tag_counter.items():
                line = f"{tag},{count}\n"
                tag_counter_log_file.write(line)
        with open("vpcflowlogparser/flow_data_parser/port_proto_count.log", "w+") as port_proto_combo_counter_log_file:
            port_proto_combo_counter_log_file.write("Port,Protocol,Count"+"\n")
            for port_proto_tuple, count in port_proto_combo_counter.items():
                port = port_proto_tuple[0]
                protocol = port_proto_tuple[1]
                line1 = f"{port},{protocol},{count}\n"
                port_proto_combo_counter_log_file.write(line1)
        return


if __name__ == "__main__":
    flpobj = FlowLogParser() #Flow log parser object
    f = flpobj.parse_lookuptable_file()
    tc, ppc = flpobj.flow_tag_count_logger()
    print(f"Flow-tags and their count of occurence in the flow log: {tc}")
    print(f"Port/Protocol combination counts in the flow log: {ppc}")
    print(f"OUTPUT is stored at follwoing files: 
    vpcflowlogparser/flow_data_parser/tag_count.log 
    vpcflowlogparser/flow_data_parser/port_proto_count.log")
    flpobj.data_logger()

