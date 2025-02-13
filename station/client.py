from NIDS.modules.NIDS import NIDS
from NIDS.helpers.is_running_as_root import is_running_as_root
from NIDS.helpers.get_logo import get_logo
import argparse

if __name__ == "__main__":
    print(get_logo())
    print("Developed by: Mohammed Alharbi")
    print("Version: v1.0.0\n")

    parser = argparse.ArgumentParser()

    # interface input
    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help="interface name for sniffing"
    )
    # Server IP input
    parser.add_argument(
        '-s', '--server',
        type=str,
        required=True,
        help="server IP address for sending alerts"
    )
    # Server port input
    parser.add_argument(
        '-p', '--port',
        type=int,
        required=True,
        help="server port number for sending alerts"
    )

    args = parser.parse_args()
    interface = args.interface
    server_ip = args.server
    server_port = args.port

    # script must be run as root
    if(not is_running_as_root()):
        print("[!] Please run the script as root")
    else:
        nids = NIDS(interface=interface, server_ip=server_ip, server_port=server_port)
        nids.start_sniffing()
