import socket
import threading

class NextRelay:
    def __init__(self, ip, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = (ip, port)

    def connect(self):
        self.client_socket.connect(self.host)
        return True

    def send(self, msg):
        self.client_socket.send(msg)

class TCPServer:
    def __init__(self, host="localhost", port=10001):
        self.server_address = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(5)

        print(f"TCP Server listening on {host}:{port}")

    def next_node(self, sock, next_relay):
        
        # Receives data to current and forwads it to next node
        while True:
            try:
                data = sock.recv(4096)
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
                data = next_relay.client_socket.recv(4096)
                print("RECEIVED",data)
                if not data:
                    print("Error")
                    next_relay.client_socket.close()
                    sock.close()
                    break
                sock.send(data)
            except Exception as e:
                print(e)
                break

    def start(self):
        try:
            while True:
                print("Waiting for a connection...")
                client_socket, client_address = self.server_socket.accept()
                next_relay = NextRelay("localhost", 10002)
                if next_relay.connect():
                    threading.Thread(target=self.next_node, args=(client_socket, next_relay,)).start()
                    threading.Thread(target=self.back_node, args=(client_socket, next_relay,)).start()

        except KeyboardInterrupt:
            print("\nShutting down the server...")
            self.server_socket.close()

if __name__ == "__main__":
    server = TCPServer(host="localhost", port=10001)
    server.start()