from NIDS.helpers.get_logo import get_logo
from NIDS.modules.Alert import Alert
from NIDS.modules.Logs import Logs
import socket
import argparse

def start_server(host='127.0.0.1', port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))

        print(f"[INFO] Alert Server started and listening on {host}:{port}")
        print(f"[INFO] Any events from client will be displayed here")

        server_socket.listen(5)

        try:
            while True:
                client_socket, client_address = server_socket.accept()
                
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        continue # if no data then skip the rest

                    # decrypt and get data
                    # the same key must be provided in both client and server 
                    # in order to decrypt data, otherwise decryption failed will araise
                    alert = Alert.from_json(data, b"1234567890123456")

                    # display data in the table
                    alert.display_table()
                    # write the alert to a log file
                    Logs('events.log').write(alert)

                except Exception as e:
                    print(f"[ERROR]: {e}")
                finally:
                    client_socket.close()
        except KeyboardInterrupt as k:
            print(f"[INFO] Exit program: {k}")


if __name__ == "__main__":
    print(get_logo())
    print("Developed by: Mohammed Alharbi")
    print("Version: v1.0.0\n")

    parser = argparse.ArgumentParser(
        description="NIDS server, responsible for alerting captured packets"
    )

    # Host IP input
    parser.add_argument(
        '-l', '--listen',
        type=str,
        required=True,
    )
    # Host port input
    parser.add_argument(
        '-p', '--port',
        type=int,
        required=True,
    )

    args = parser.parse_args()

    listen = args.listen
    port = args.port

    start_server(host=listen, port=port)