# ipt_tcpbreak
Break TCP-connect (linux netfilter target extension)

Sending optional string to client, send tcp-reset to client,  send tcp-reset to server and break conntrack connection.

The minimum requirements for the kernel configuration
 CONFIG_NF_CONNTRACK=m or y
 
Developed for kernel 4.X (tested on 4.8.6)

Example:
```
 # iptables -A FORWARD -m state --state INVALID -j DROP
 # iptables -A FORWARD -p tcp --dport 8080 -m string --string "GET " --algo bm -j TCPBREAK --http302 'http://localhost/'
 # iptables -A INPUT -m state --state INVALID -j DROP
 # iptables -A INPUT -p tcp --dport 8080 -m string --string "GET " --algo bm -j TCPBREAK --http302 'http://localhost/'
 # iptables -A INPUT -p tcp --dport 25 -m string --string "ehlo" --algo bm -j TCPBREAK --raw 'quit'
```
