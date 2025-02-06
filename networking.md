# OT (Ethernet/IP Devices) port : 44818
# IOT (BACnet Devices) port: 48101




### **FTP (File Transfer Protocol) 20/21**: 
    Used for transferring files between a client and a server. Port 20 is used for data transfer, and port 21 is used for control (commands). #ceh

### **SSH (Secure Shell) 22**: 
    Used for secure logins, file transfers (SCP, SFTP), and port forwarding.

### **Telnet 23**: 
    Used for unencrypted text communications over a network. (Insecure, often replaced by SSH)

### **SMTP (Simple Mail Transfer Protocol) 25**: 
    Used for sending emails.

### **DNS (Domain Name System) 53**: 
    Translates domain names into IP addresses. 
    
### **HTTP (Hypertext Transfer Protocol) 80**: 
    Used for transferring web pages over the internet.

### **POP3 (Post Office Protocol version 3) 110**: 
    Used by email clients to retrieve emails from a server.

### **NTP (Network Time Protocol) 123**:
	Uses UDP packets for data transfer because of the fast connection setup and response times.
	
### **MSRPC (Microsoft RPC) 135**: 
    Used for remote procedure calls in Microsoft networks.

### **NetBIOS 137-139**: 
     Used for file sharing and other network services in older Windows networks.

### **IMAP (Internet Message Access Protocol) 143**: 
    Used by email clients to retrieve and manage email on a server.

### **SNMP (Simple Network Management Protocol) 161/162**: 
     Used for managing devices on IP networks.
     
### **LDAP (Lightweight Directory Access Protocol) 389**: 
    Used for accessing and maintaining distributed directory information services.

## **LDAPS 636**
    
### **HTTPS (Hypertext Transfer Protocol Secure) 443**: 
    Secure version of HTTP, used for secure communication over a computer network.
    
### **SMB (Server Message Block) 445**: 
     Used for providing shared access to files, printers, and serial ports between nodes on a network.

### **IMAPS (Internet Message Access Protocol Secure) 993**: 
    Secure version of IMAP, used to retrieve emails securely.

### **POP3S (Post Office Protocol Secure) 995**: 
     Secure version of POP3, used to retrieve emails securely.

### **MySQL 3306**: 
    Used for database connections.

### **RDP (Remote Desktop Protocol) 3389**: 
    Used for remote desktop connections.

### **HTTP Proxy / Alternative HTTP 8080**: 
    Often used as an alternative port for HTTP services or proxy servers.

# Attacks:
- **Spoofed session flood attack**: In this type of attack, the attacker sends a series of packets that appear to be part of a legitimate TCP session. By using SYN, ACK, RST, and FIN packets in patterns that mimic normal traffic, the attack can bypass security mechanisms that only monitor incoming traffic and do not adequately validate the state of the sessions. This allows the attacker to flood the target with traffic that appears legitimate, overwhelming the system.

- **Ping-of-death attack**: This attack involves sending malformed or oversized packets to a target, causing crashes or disruptions. It doesn't involve spoofed TCP sessions with SYN, ACK, RST, or FIN packets.

- **UDP flood attack**: This attack involves overwhelming the target with a flood of UDP packets. Since UDP is a connectionless protocol, it does not rely on SYN, ACK, RST, or FIN packets, making it unrelated to the scenario described.

- **Peer-to-peer attack**: This involves exploiting peer-to-peer networks to direct traffic to a victim, causing a flood. It doesn't specifically involve spoofing TCP sessions.


## TCP flags

1. **SYN (Synchronize)**:
    - **Purpose**: Used to initiate a connection between two devices.
    - **Example**: When you connect to a website, your computer sends a SYN flag to the server to start the communication process.
2. **ACK (Acknowledgment)**:
    - **Purpose**: Confirms the receipt of data or connection requests.
    - **Example**: After receiving the SYN flag from your computer, the server replies with a SYN-ACK, acknowledging the connection request and agreeing to connect.
3. **FIN (Finish)**:
    - **Purpose**: Used to gracefully close a connection.
    - **Example**: When you’re done with a website, your computer sends a FIN flag to the server, signaling that it wants to end the connection.
4. **RST (Reset)**:
    - **Purpose**: Abruptly ends a connection, often used if there’s an error or if the connection is no longer valid.
    - **Example**: If something goes wrong during communication, one side might send a RST flag to immediately stop the connection.
5. **PSH (Push)**:
    - **Purpose**: Instructs the receiving end to process the data immediately, rather than waiting for more data to arrive.
    - **Example**: If you're sending a message that needs to be processed right away, the PSH flag ensures the data is delivered to the application immediately.
6. **URG (Urgent)**:
    - **Purpose**: Indicates that some data is urgent and should be processed before anything else.
    - **Example**: If you're sending a critical alert, the URG flag prioritizes this data over other packets.

In summary:

- **SYN**: Start connection.
- **ACK**: Acknowledge receipt.
- **FIN**: End connection.
- **RST**: Abort connection.
- **PSH**: Push data immediately.
- **URG**: Prioritize urgent data.

# NetBIOS 
Network Basic Input Output System. It Allows computer communication over a LAN and allows them to share files.


![01](assets/submask.png)
