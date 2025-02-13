import json

class Rules:
    def __init__(self, packet, connection_state):
        self.packet = packet[0][1]
        self.eth_layer = packet[0][0]
        self.connection_state = connection_state
        self.severity_level = False # severity False means Normal traffic

        # register checking methods here 
        self.rules = [
            self.check_packet_count,
            self.check_packet_size,
            self.check_arp_requests,
        ]

        # Load configuration from the config.json file
        with open("NIDS/config.json", "r") as file:
            self.config = json.load(file)

    def check_packet_count(self):
        """Check if packet count exceeds the threshold."""
        for severity, thresholds in self.config.items():
            if self.connection_state and self.connection_state.get('packet_count', 0) > thresholds.get("packet_count_threshold", float("inf")):
                self.severity_level = severity
        return False

    def check_packet_size(self):
        """Check if total packet size exceeds the threshold."""
        for severity, thresholds in self.config.items():
            if self.connection_state and self.connection_state.get('total_size', 0) > thresholds.get("packet_size_threshold", float("inf")):
                self.severity_level = severity
        return False
    
    def check_arp_requests(self):
        """Check if ARP requests from a source exceed the threshold."""
        if self.connection_state.get('protocol') == 'ARP':
            arp_count = self.connection_state.get('packet_count', 0)
            for severity, thresholds in self.config.items():
                if arp_count > thresholds.get("arp_request_threshold", 0):
                    self.severity_level = severity
        return False
    

    
    def start_checking(self):
        if not self.connection_state:
            return False

        for rule in self.rules:
            rule() 

        return self.severity_level  