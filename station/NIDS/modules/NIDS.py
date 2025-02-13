from NIDS.modules.Alert import Alert
from NIDS.modules.Rules import Rules
from NIDS.modules.Session import Session
from NIDS.helpers.get_protocol_name import get_protocol_name
from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from datetime import datetime
import socket

class NIDS:
    def __init__(self, interface, server_ip, server_port):
        self.alerts = []
        self.interface = interface  
        self.server_ip = server_ip
        self.server_port = server_port
        self.session = Session()

    def detect_malicious_traffic(self, packet):
        if packet.haslayer(Ether) and not packet.haslayer(IP):
            src_address = packet[0].src
            dst_address = packet[0].dst
            proto = packet[0].type
            proto_name = get_protocol_name(proto, layer="ethernet")
            srcport = None
            deport = None
            flags = None
        elif packet.haslayer(IP):
            src_address = packet[0][1].src if hasattr(packet[0][1], 'src') else None
            dst_address = packet[0][1].dst if hasattr(packet[0][1], 'dst') else None
            proto = packet[0][1].proto if hasattr(packet[0][1], 'proto') else None
            srcport = packet[0][1].sport if hasattr(packet[0][1], 'sport') else None
            deport = packet[0][1].dport if hasattr(packet[0][1], 'dport') else None
            proto_name = get_protocol_name(proto, layer="internet")
            flags = None  # if not TCP layer

            if packet.haslayer(TCP):
                flags = str(packet[0][2].flags) 
    
        payload = packet[0][1].payload if hasattr(packet[0][1], 'payload') else None
        packet_size = len(packet)

        self.session.update(src_address, dst_address, proto_name, deport, packet_size)

        connection_state = self.session.get(src_address, dst_address, proto_name, deport)

        # start checking the packet from all the defined rules, if match it will return severity level
        severity = Rules(packet, connection_state).start_checking()

        #  Only catch packets based on defined rules
        if severity:
            alert = Alert(
                alert_level=severity,
                src_ip=src_address,
                dst_ip=dst_address,
                protocol=proto_name,
                timestamp=datetime.now().strftime('%H:%M:%S'),
                deport=deport,
                srport=srcport,
                payload=payload,
                packet_size=packet_size,
                flags=flags
            )
            
            # encrypt data and decode it
            data = alert.to_json()

            # send encoded data to the server
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.server_ip, self.server_port))
                    s.sendall(data.encode('utf-8'))
                    print('[!] Data sent to server successfully')
            except Exception as e:
                print(f"{e}")

    def start_sniffing(self):
        print("[INFO] NIDS is running and sniffing network traffic on interface: ", self.interface)
        sniff(iface=self.interface, prn=self.detect_malicious_traffic, store=False)