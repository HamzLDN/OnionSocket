import struct


class coms:
    def send(self, sock, message):
        sock.sendall(struct.pack(">I", len(message)) + message)

    def recv(self, client_sock):
        msg_len = self.receive_all(client_sock, 4)
        if msg_len is None:
            return None
        length = struct.unpack(">I", msg_len)[0]
        return self.receive_all(client_sock, length)

    def receive_all(self, client_sock, n):
        data = b""
        while len(data) < n:
            packet = client_sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data
