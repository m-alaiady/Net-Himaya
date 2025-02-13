Welcome To Net HiMaya Tool (NIDS)

To run the program do these steps:
1. First run server.py
    usage: python3 server.py [-h] -l LISTEN -p PORT
2. then run client.py 
    usage: python3 client.py [-h] -i INTERFACE -s SERVER_IP -p SERVER_PORT [-v]
3. You might need to change the default configuration file which can be found in
NIDS/config.json, based on these rules the NIDS will classify incoming packet based on their severity level

Any displayed alerts will be stored in logs/events.log





