import socket
from src.symmetric import aes

class TCPClient:
    def __init__(self, host="localhost", port=10001):
        self.server_address = (host, port)
        self.enc_method = {"AES", b'\x21'}

    def setup(self, sock, enc):
        if enc in self.enc_method:
            sock.send(self.enc_method[enc])

    def establish_secure_connection(self):
        pass

    def start(self, enc="AES"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(self.server_address)
            self.setup(client_socket, "AES")
            while True:
                try:
                    client_socket.send(input("Send message: ").encode())
                    print(client_socket.recv(1028))
                except KeyboardInterrupt:
                    client_socket.close()

if __name__ == "__main__":
    client = TCPClient(host="localhost", port=10001)
    client.start()