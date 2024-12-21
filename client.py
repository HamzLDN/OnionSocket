import socket
from src.symmetric import aes
from src.asymmetric import rsa
from src import tcp_enhancer

class TCPClient:
    def __init__(self, host="localhost", port=10001):
        self.server_address = (host, port)
        self.enc_method = {"AES": '\x21'}
        self.coms = tcp_enhancer.coms()

    def setup(self, sock, enc):
        if enc in self.enc_method:
            self.coms.send(sock, self.enc_method[enc].encode())
            self.establish_secure_connection(sock)

    def establish_secure_connection(self, sock):
        private_key, public_key = rsa.generate_rsa_keys()
        self.coms.send(sock, rsa.export_public_key(public_key))
        server_public_key = rsa.load_public_key(self.coms.recv(sock))
        print(self.coms.recv_enc(sock, server_public_key, private_key))

    def start(self, enc="AES"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(self.server_address)
            self.setup(client_socket, enc)
            while True:
                try:
                    self.coms.send(client_socket, input("Send message: ").encode())
                    print(self.coms.recv(client_socket))
                except KeyboardInterrupt:
                    client_socket.close()

if __name__ == "__main__":
    client = TCPClient(host="localhost", port=10001)
    client.start()