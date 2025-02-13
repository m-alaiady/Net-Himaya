class Logs:
    def __init__(self, filename):
        self.file = filename

    def write(self, alert):
        """Add an alert to the log file

        Args:
            alert (Alert): alert object
        """
        with open(f"logs/{self.file}", "a") as f:
            f.write(f"[{alert.alert_level}] {alert.src_ip}:{alert.srport} > {alert.dst_ip}:{alert.deport} at {alert.timestamp}\nFlags: {alert.flags}\nPayload: {alert.payload}\n")
        

