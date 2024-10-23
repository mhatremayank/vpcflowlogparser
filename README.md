# vpcflowlogparser
This tool analyzes and produces matching records for flow logs of a given VPC
The maximum file size for a default flow log in Amazon Web Services (AWS) is 10-75 MB for this tool

https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.htm


Main parser class (aka FlowLogParser) expects flowlog data and lookup table data to be present in their assigned directory paths.
FlowLogParser is designed in such a way that even if files are not present in the directories, it can be passed to the main method for testing purposes.
FlowLogParser methods can be extended beyond original parsing logic.

Assumptions:
- Flow Log size is upto 10MB max. This is given the fact that machine shall have a memory to support 10MB data loading and data accessing. Positive side of it is you will get a quick parsing and fast lookups
- Adjacent methods/utilities can be added to have flow-log cycling policies and have it uploaded to S3 bucket using AWS botocore SDK or remote storage/databases for retention (To do)
- It is assumed that protocol number field in flow log file will not deviate from IANA standards, hence the tool utilizes IANA apporved CSV file at https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml and create a mapping of number (INT_32) to protocol type (STRING)
- It is assumed that flowlog data is going to be valid. Class can be extended to accomodate data validation methods so that entire flow log file can be validated and we can catch data inconsistency at every line

Prerequisites:
- User need to have flowlog file at /flow_datastore/ and lookup table file at /lookup_table_store

```
DIRECTORY STRUCTURE:
├── LICENSE
    ├── README.md
    ├── __init__.py
    ├── flow_data_parser
    │   ├── __init__.py
    │   └── fparser.py
    ├── flow_datastore
    │   ├── __init__.py
    │   └── flowlogs_v2.txt
    ├── lookup_table_store
    │   ├── __init__.py
    │   └── lookup_table.txt
    ├── main.py
    └── protocol_mapper
        ├── __init__.py
        ├── protocol-numbers-1.csv
        └── protocol_number_mapper.py
```

# How to run this program?
This program can be run as a module in following way
<!-- (Make sure to be outside the parent module path to avoid ModuleNotFoundError: No module named 'vpcflowlogparser' error) -->
```$ python3 -m vpcflowlogparser.flow_data_parser.fparser```

Expected Output:
```
Flow-tags and their count of occurence in the flow log: {'untagged': 8, 'sv_p2': 1, 'sv_p1': 2, 'email': 7}
Port/Protocol combination counts in the flow log: {(49153, 'tcp'): 1, (49154, 'tcp'): 1, (49155, 'tcp'): 1, (49156, 'tcp'): 1, (49157, 'tcp'): 1, (49158, 'tcp'): 1, (80, 'tcp'): 1, (1024, 'tcp'): 1, (443, 'tcp'): 1, (23, 'tcp'): 1, (25, 'tcp'): 1, (110, 'tcp'): 1, (993, 'tcp'): 3, (143, 'tcp'): 3}
```

Output Files will be created at:
```vpcflowlogparser/flow_data_parser/tag_count.log```
```vpcflowlogparser/flow_data_parser/port_proto_count.log```

Flow Diagram:
![image](https://github.com/user-attachments/assets/5b3c5b51-b771-4533-95ab-fad806f70b6f)


