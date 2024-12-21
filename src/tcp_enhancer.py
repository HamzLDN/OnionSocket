import socket, struct
from src.asymmetric import rsa

class coms:
    def __init__(self):
        pass

    def send(self, sock, message):
        sock.sendall(struct.pack('>I', len(message)) + message)

    def recv(self, client_sock):
        msg_len = self.receive_all(client_sock, 4)
        if not msg_len: return None
        return self.receive_all(client_sock, struct.unpack('>I', msg_len)[0])

    def receive_all(self, client_sock, n):
        data = b''
        while len(data) < n:
            packet = client_sock.recv(n - len(data))
            if not packet: return None
            data += packet
        return data
    
    def recv_enc(self, sock, public_key, private_key):
        try:
            data = self.recv(sock)
            signature = data[len(data)-256:]
            message = rsa.decrypt_message(private_key, data[:len(data)-256])
            if rsa.verify_signature(public_key, message, signature):
                return message
            else:
                print("DATA COULD NOT BE SIGNED")
                return False
        except Exception as e:
            print("SOMETHING UNEXPECTED HAPPENED", e)
            
    def send_enc(self, sock, message, public_key, private_key):
        signature = rsa.sign_message(private_key, message)
        print(signature)
        enc_msg = rsa.encrypt_message(public_key, message)
        enc_msg += signature
        sock.sendall(struct.pack('>I', len(enc_msg)) + enc_msg)