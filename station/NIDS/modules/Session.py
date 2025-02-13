from datetime import datetime

class Session:
    def __init__(self):
        # keep tracking packets in this variable 
        self.connections = {}  
        # ARP requests will be stored separately here
        self.arp_requests = {} 

    def update(self, src_ip, dst_ip, protocol, port, size):
        """Update connections session

        Args:
            src_ip (str): Source Address
            dst_ip (str): Destination Address
            protocol (str): Protocol name
            port (int): Port number
            size (int): Packet size
        """
        key = (src_ip, dst_ip, protocol, port)

        if key not in self.connections:
            # keep track of packet
            self.connections[key] = {
                'start_time': datetime.now(),
                'total_size': 0, 
                'packet_count': 0,
                'protocol': protocol,
            }

        self.connections[key]['total_size'] += size
        # whenever there is a packet from same source keep counting
        self.connections[key]['packet_count'] += 1

    def get(self, src_ip, dst_ip, protocol, port):
        """Get the connection state from the connections

        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            protocol (str): Protocol name
            port (int): Port number

        Returns:
            Connection state
        """
        key = (src_ip, dst_ip, protocol, port)

        return self.connections.get(key, None)
