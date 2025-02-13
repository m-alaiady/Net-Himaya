# Network Intrusion Detection System (NIDS)
<img width="943" alt="image" src="https://github.com/user-attachments/assets/80432fc0-446c-4797-89ef-5845f2f1ee74" />

## 1. Introduction
The Network Intrusion Detection System (NIDS) program has been developed to monitor network traffic and detect adversarial scanning techniques and attacks, such as TCP and ARP ports as well as DDoS attacks. This program is named **"Net Himaya"**, which translates to **"Network Protection"**, where *"Himaya"* is an Arabic word meaning *"protection"* in English.  

This program is designed with high quality and scalability, allowing for easy rule extension to accommodate future developments. This report provides a brief overview of the program, its functionality, key features, and limitations.  

## 2. Self-Assessment  

### Features:  

1. **Dynamic Severity Levels**:  
   - The program dynamically changes severity levels based on continued adversary attacks.  
   - An alert may initially classify an attack as *Low*, but if it escalates, it will be changed to *Critical*.  
   - This proactive classification helps prevent operational disruptions and prioritize higher-priority alerts.  

2. **Easy Configuration and Rule Extension**:  
   - A configuration file (`config.json`) within the NIDS directory allows users to modify settings easily.  
   - The file includes four severity levels (*Low* to *Critical*), each containing three threshold values.  
   - New detection rules can be seamlessly added to the `Rules.py` file.  

3. **User-Friendly Data Representation**:  
   - The program elegantly processes and presents data in a **colour-coded table**, enhancing readability.  
   - Logged events in `events.log` are structured in an easily interpretable format.  

4. **Secure Communication**:  
   - The program incorporates **AES-CBC encryption** to ensure secure communication between the client and server using a predefined key.  
   - Additionally, a **CRC checksum** has been implemented to verify data integrity.  

5. **DDoS Attack Detection**:  
   - The program can detect network packets with **abnormally high payloads**, enabling it to identify potential DDoS attacks.  

### Limitations:  

1. **Potential False Positives**:  
   - The program may generate **false positive** alerts, especially if the threshold values in the configuration file are set too low.  

2. **Limited Payload Inspection**:  
   - The program does not analyze packet payloads, making it **incapable** of detecting injection attacks such as **SQL injection** or **OS command injection**.  

3. **Limited Effectiveness Against Evasion Techniques**:  
   - The program relies on **stored IP addresses** as identifiers, which may fail to detect **malicious sources using evasion tactics**.  

## 3. Flowchart  
<img width="460" alt="image" src="https://github.com/user-attachments/assets/48f08d22-b81d-48c8-9254-fc128b3ab0e2" />



## 4. Detection Approach  

The implemented detection mechanism primarily relies on **monitoring traffic patterns** and identifying abnormal behaviours based on predefined threshold values. It tracks parameters such as:  
- **Request frequency**  
- **Session persistence**  
- **Deviation from normal usage patterns**  

The approach is designed to detect **volumetric attacks** like DDoS by analyzing the rate of incoming requests and issuing alerts if abnormal packet activity is observed. Moreover, it leverages **session-based tracking** to associate requests with specific IP addresses.  

### Limitations:  
- **Threshold-based detection** may lead to **false positives** if limits are too low or **false negatives** if the attack is slow and distributed.  
- The system **does not inspect packet payloads**, making it ineffective against injection-based attacks such as **SQL injection**.  
- Attackers can use **evasion techniques** like **IP spoofing** or **distributed attack patterns**, making it difficult to attribute malicious activity to a specific source.  

### Future Improvements:  
To improve this program, future implementations should include:  
1. **Machine learning integration** for adaptive anomaly detection using an **unsupervised Isolation Forest algorithm**.  
2. **Deep packet inspection (DPI)** for more comprehensive threat identification.  
3. **Tracking packets using a unique identifier (other than IP addresses)** to detect evasion techniques like **IP spoofing in DDoS attacks**.  

## 5. Secure Communication Critique  

This program incorporates **secure communication** between the Client and Server using **AES-CBC cryptography** with a password to ensure **data confidentiality**. Additionally, a **CRC checksum** has been implemented to verify data integrity.  

Before transmission, the data is **Base64-encoded** for easier handling. The payload consists of two sections:  

1. **Header**: Stores encryption information and CRC checksum.  
2. **Data**: Stores alert data such as **Source and Destination IP addresses**. This data is wrapped in **JSON format** before being sent to the server.  

### Security Considerations:  
- **AES encryption relies on a password**—if this password is exposed, the data can be easily decrypted.  
- The program uses a **default password**, which should be replaced with a **stronger** and more secure password.  
- It is crucial to store encryption keys in a **safe place** to prevent unauthorized access.  
