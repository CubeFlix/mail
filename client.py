import socket

# HOST = '127.0.0.1'
PORT = 65432

def client(host, username, password, data):
    request = bytes(username + '\n' + password + '\n' + data, encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((host, PORT))
        s.sendall(bytes(b'KMAIL' + len(request).to_bytes(4, "little") + request))
        if s.recv(5) != b"KMAIL":
            return
        length = int.from_bytes(s.recv(4), "little")
        data = s.recv(length)
        return data

def ping(host):
    request = bytes(" PING", encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((host, PORT))
        s.sendall(bytes(b'KMAIL' + len(request).to_bytes(4, "little") + request))
        if s.recv(5) != b"KMAIL":
            return
        length = int.from_bytes(s.recv(4), "little")
        data = s.recv(length)
        return data

def outofnetworksend(host, sender, recipients, body):
    request = bytes(" NETWORKSEND\n" + sender + "\n" + recipients + "\n" + body, encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((host, PORT))
        s.sendall(bytes(b'KMAIL' + len(request).to_bytes(4, "little") + request))
        if s.recv(5) != b"KMAIL":
            return
        length = int.from_bytes(s.recv(4), "little")
        data = s.recv(length)
        return data