import socket
import threading
from src.symmetric import aes
from src.asymmetric import rsa
from src import tcp_enhancer
class NextRelay:
    def __init__(self, ip, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = (ip, port)
        self.coms = tcp_enhancer.coms()
    def connect(self):
        self.client_socket.connect(self.host)
        return True

    def send(self, msg):
        self.coms.send(self.client_socket, msg)

    def recv(self, sock):
        return self.coms.recv(sock)

class TCPServer:
    def __init__(self, host="localhost", port=10001):
        self.server_address = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(5)
        self.encryption_type = {'\x21': aes}
        self.coms = tcp_enhancer.coms()
        self.client_public_key = None
        print(f"TCP Server listening on {host}:{port}")

    def next_node(self, sock, next_relay):
        
        # Receives data to current and forwads it to next node
        while True:
            try:
                data = self.coms.recv(sock)
                if not data:
                    sock.close()
                    next_relay.close()
                    break
                next_relay.send(data)
            except Exception as e:
                break

    def back_node(self, sock, next_relay):
        
        # We will get data from the next node and send it back to the connected client
        while True:
            try:
                data = next_relay.recv(sock)
                print("RECEIVED",data)
                if not data:
                    print("Error")
                    next_relay.client_socket.close()
                    sock.close()
                    break
                self.coms.send(sock, data)
            except Exception as e:
                print(e)
                break

    def setup(self, sock):
        data = self.coms.recv(sock).decode()
        if data in self.encryption_type:
            self.enc = self.encryption_type[data]
            self.establish_secure_connection(sock)

    def establish_secure_connection(self, sock):
        private_key, public_key = rsa.generate_rsa_keys()
        self.coms.send(sock, rsa.export_public_key(public_key))
        self.client_public_key = rsa.load_public_key(self.coms.recv(sock))
        self.coms.send_enc(sock, b"Hello", self.client_public_key, private_key)

    def start(self):
        try:
            while True:
                print("Waiting for a connection...")
                client_socket, client_address = self.server_socket.accept()
                next_relay = NextRelay("localhost", 10002)
                self.setup(client_socket)
                if next_relay.connect():
                    threading.Thread(target=self.next_node, args=(client_socket, next_relay,)).start()
                    threading.Thread(target=self.back_node, args=(client_socket, next_relay,)).start()

        except KeyboardInterrupt:
            print("\nShutting down the server...")
            self.server_socket.close()

if __name__ == "__main__":
    server = TCPServer(host="localhost", port=10001)
    server.start()