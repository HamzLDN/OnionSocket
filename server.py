import socket
import threading


class TCPServer:
    def __init__(self, host="localhost", port=10003):
        self.server_address = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(5)

    def start(self):
        try:
            print("Waiting for a connection...")
            client_socket, client_address = self.server_socket.accept()
            while True:

                data = client_socket.recv(4096)
                if not data:
                    client_socket.close()
                    self.server_socket.close()
                    break
                else:
                    print("SENDING DATA", data)
                    client_socket.send(data)


        except KeyboardInterrupt:
            print("\nShutting down the server...")
            self.server_socket.close()

if __name__ == "__main__":
    server = TCPServer(host="localhost", port=10003)
    server.start()