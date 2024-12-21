import socket
class TCPClient:
    def __init__(self, host="localhost", port=10001):
        self.server_address = (host, port)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(self.server_address)
            while True:
                try:
                    client_socket.send(input("Send message: ").encode())
                    print(client_socket.recv(1028))
                except KeyboardInterrupt:
                    client_socket.close()

if __name__ == "__main__":
    client = TCPClient(host="localhost", port=10001)
    client.start()