import socket, signal, os, sys, threading
import uuid, pickle
import client

HOST = '127.0.0.1'
GLOBAL_ADDR = ''
PORT = 65432
USERS_FILE = "users.dat"
MESSAGES_FILE = "messages.dat"
TIMEOUT = 10
VB = False

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.new_messages = []

class Message:
    def __init__(self, uuid, sender, recipients, body):
        self.uuid = uuid
        self.sender = sender
        self.recipients = recipients
        self.body = body

# Load the users.
def load_users():
    return pickle.load(open(USERS_FILE, "rb"))

# Load the messages.
def load_messages():
    return pickle.load(open(MESSAGES_FILE, "rb"))

# Save.
def save():
    global users, messages
    pickle.dump(users, open(USERS_FILE, "wb"))
    pickle.dump(messages, open(MESSAGES_FILE, "wb"))

# Global runtime variables.
users = {}
messages = {}

# Send a message.
def send(sender, recipients, body):
    global users, messages
    message_id = uuid.uuid4()
    messages[message_id] = Message(message_id, sender, recipients, body)
    for i in recipients:
        if not i in users.keys():
            continue
        users[i].new_messages.append(message_id)

# Send to out-of-network users.
def sendOutOfNetwork(sender, recipients, body):
    # Sort into networks.
    networks = {}
    for i in recipients:
        if len(i.split("@")) != 2:
            return "Invalid out-of-network identifier."
        user = i.split("@")
        if user[1] in networks.keys():
            networks[user[1]].append(user[0])
        else:
            networks[user[1]] = [user[0]]

    # Ping each network.
    for i in networks.keys():
        if str(client.ping(i), "utf-8") != "Success.":
            return "Failed to ping all recipient client servers: " + i

    # Send to each network.
    error = False
    errors = []
    for ip, users in networks.items():
        resp = str(client.outofnetworksend(ip, sender + "@" + GLOBAL_ADDR, ' '.join(users), body), "utf-8")
        if len(resp.split("\n")) < 1:
            error = True
            errors.append("Error from " + ip + ": Invalid server response")
        if resp.split("\n")[0] != "Success.":
            error = True
            errors.append("Error from " + ip + ": " + resp.split("\n")[0])
    if error:
        return ", ".join(errors)

    return "sent"

# Out-of-network send, on the recipient server.
def serverSideNetworkSend(sender, recipients, body):
    global users, messages
    message_id = uuid.uuid4()
    messages[message_id] = Message(message_id, sender, recipients, body)
    for i in recipients:
        if not i in users.keys():
            continue
        users[i].new_messages.append(message_id)
    return bytes("Success.", encoding="utf-8")

# Receive a message.
def recv(message_id):
    global users, messages
    if not message_id in messages.keys():
        return bytes("Message ID invalid.", encoding="utf-8")
    return bytes("Success.\n" + messages[message_id].sender + "\n" + messages[message_id].body, encoding="utf-8")

# Get the new messages for a user.
def new_messages(username):
    global users, messages
    new_messages = users[username].new_messages
    users[username].new_messages = []
    return bytes("Success.\n" + "\n".join([str(i) for i in new_messages]), encoding="utf-8")

# Get all the messages for a user.
def all_messages(username):
    global users, messages
    ids = []
    for uuid, message in messages.items():
        if username in message.recipients:
            ids.append(uuid)
    users[username].new_messages = []
    return bytes("Success.\n" + "\n".join([str(i) for i in ids]), encoding="utf-8")

# Request handler.
def handleRequest(data, addr):
    global users, messages
    try:
        content = str(data, encoding="utf-8")
        lines = content.split("\n")
        if len(lines) == 1 and lines[0].upper() == " PING":
            # Ping command. We use a space before "PING" to differentiate usernames from commands.
            return bytes("Success.", encoding="utf-8")
        if len(lines) > 3 and lines[0].upper() == " NETWORKSEND":
            # Verify the authenticity of the server.
            if len(lines[1].split("@")) != 2:
                return bytes("Invalid sender identifier.")
            if socket.gethostbyname(lines[1].split("@")[1]) != addr[0]:
                return bytes("Cannot verify server authenticity.")
            # Out-of-network send command, only comes from servers.
            recipients = lines[2].split(" ")
            allempty = True
            for i in recipients:
                if i:
                    allempty = False
                    break
            if allempty:
                return bytes("No recipients.", encoding="utf-8")
            return serverSideNetworkSend(lines[1], recipients, "\n".join(lines[3:]))
        if len(lines) < 3:
            return bytes("Invalid request data.", encoding="utf-8")
        
        # Log in.
        if not lines[0] in users.keys():
            return bytes("Invalid user.", encoding="utf-8")
        if users[lines[0]].password != lines[1]:
            return bytes("Invalid password.", encoding="utf-8")

        # Get the command.
        command = lines[2]
        if command.upper() == "SEND":
            # Send command.
            recipients = lines[3].split(" ")
            allempty = True
            for i in recipients:
                if i:
                    allempty = False
                    break
            if allempty:
                return bytes("No recipients.", encoding="utf-8")

            # Find out-of-network recipients.
            outOfNetwork = []
            for i in recipients:
                if "@" in i:
                    outOfNetwork.append(i)
            if outOfNetwork != []:
                status = sendOutOfNetwork(lines[0], outOfNetwork, "\n".join(lines[4:]))
                if status != "sent":
                    return bytes(status, encoding="utf-8")
            send(lines[0], recipients, "\n".join(lines[4:]))
        elif command.upper() == "RECV":
            # Receive command.
            message_id = uuid.UUID(lines[3])
            return recv(message_id)
        elif command.upper() == "NEW":
            # Get new messages.
            return new_messages(lines[0])
        elif command.upper() == "REG":
            # Register a new user.
            if lines[0] in users.keys():
                # User already exists.
                return bytes("User already exists.", encoding="utf-8")
            if " " in lines[0]:
                # Invalid username.
                return bytes("Username may not contain spaces or @ symbols.", encoding="utf-8")
            if not lines[0]:
                return bytes("Username may not be empty.", encoding="utf-8")
            users[lines[0]] = User(lines[0], lines[1])
        elif command.upper() == "DEL":
            # Delete a user.
            del users[lines[0]]
        elif command.upper() == "ALL":
            # Get all message IDs.
            return all_messages(lines[0])
        elif command.upper() == "AUTH":
            # Authenticate the user.
            pass
        else:
            return bytes("Invalid command.", encoding="utf-8")
        return bytes("Success.", encoding="utf-8")

    except Exception as e:
        return bytes("Error while handling request: " + str(e), encoding="utf-8")

def serve():
    # Mail server.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(5)
            while True:
                try:
                    conn, addr = s.accept()
                    conn.settimeout(10)
                    threading.Thread(target=lambda: handle_conn(conn, addr)).start()
                except Exception as e:
                    print("Error handling connection:", e)
    except KeyboardInterrupt:
        # Keyboard interrupt.
        print("Server closing.")

def handle_conn(conn, addr):
    try:
        with conn:
            if VB:
                print('Connection: ', addr)
            header = conn.recv(5)
            if header != b"KMAIL":
                return
            length = int.from_bytes(conn.recv(4), "little")
            data = conn.recv(length)
            
            # Handle the connection.
            response = handleRequest(data, addr)
            save()
            conn.sendall(b"KMAIL" + len(response).to_bytes(4, "little"))
            conn.sendall(response)
    except Exception as e:
        # Exception.
        print("Error handling connection:", e)

def main():
    global users, messages
    global GLOBAL_ADDR, HOST
    sys.args = sys.argv
    sys.argn = len(sys.args)
    if sys.argn < 2:
        print("KMail Server.")
        print("Usage: progName <command> [args]")
        return
    command = sys.args[1]
    if command == "serve":
        if sys.argn < 3:
            print("serve requires global ip")
            return
        GLOBAL_ADDR = sys.args[2]
        HOST = GLOBAL_ADDR
        if sys.argn == 5:
            USERS_FILE = sys.args[3]
            MESSAGES_FILE = sys.args[4]
        users = load_users()
        messages = load_messages()
        threading.Thread(target=serve).start()
        try:
            while True:
                pass
        except KeyboardInterrupt:
            os._exit(0)
    elif command == "init":
        if sys.argn == 4:
            USERS_FILE = sys.args[2]
            MESSAGES_FILE = sys.args[3]
        save()
    elif command == "au":
        if sys.argn < 4:
            print("command au requires at least 2 args")
            return
        if sys.argn == 5:
            USERS_FILE = sys.args[4]

        users = load_users()
        messages = load_messages()
        if " " in sys.args[2]:
            print("username may not contain spaces or @ symbols")
            return
        if not sys.args[2]:
            print("username may not be empty")
            return
        users[sys.args[2]] = User(sys.args[2], sys.args[3])
        save()
    else:
        print("invalid command")

if __name__ == "__main__":
    main()
