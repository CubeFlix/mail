import client
from tkinter import *
from tkinter import messagebox

HOST = "127.0.0.1"
LOGGED_IN = False
USERNAME, PASSWORD = "", ""

# Login window.
def login(root, listbox, refresh_button, view_button, compose_button):
	login_tk = Toplevel()
	login_tk.geometry('200x150')
	login_tk.title('KMail Client - Login')
	login_tk.protocol("WM_DELETE_WINDOW", lambda: close_all(root))

	usernameLabel = Label(login_tk, text="Username").grid(row=0, column=0)
	username = StringVar()
	usernameEntry = Entry(login_tk, textvariable=username).grid(row=0, column=1)  
	
	passwordLabel = Label(login_tk,text="Password").grid(row=1, column=0)  
	password = StringVar()
	passwordEntry = Entry(login_tk, textvariable=password, show='*').grid(row=1, column=1)  
	
	ipLabel = Label(login_tk, text="Server IP").grid(row=2, column=0)
	ip = StringVar()
	ipEntry = Entry(login_tk, textvariable=ip).grid(row=2, column=1)
	
	command = lambda: try_login(ip, username, password, login_tk, listbox, refresh_button, view_button, compose_button)
	loginButton = Button(login_tk, text="Login", command=command).grid(row=4, column=0)
	login_tk.wm_transient(root)
def close_all(root):
	global LOGGED_IN
	if not LOGGED_IN:
		root.destroy()

def try_login(ip, username, password, login_tk, listbox, refresh_button, view_button, compose_button):
	global USERNAME, PASSWORD, LOGGED_IN, HOST
	HOST = ip.get()
	u, p = username.get(), password.get()
	message = ""
	try:
		message = client.client(HOST, u, p, "AUTH")
	except Exception as e:
		message = str(e)
	if message != b"Success.":
		error(message)
		return
	else:
		LOGGED_IN = True
		USERNAME, PASSWORD = u, p
		refresh_button["state"] = "normal"
		view_button["state"] = "normal"
		compose_button["state"] = "normal"
		msgs = all_messages(USERNAME, PASSWORD)
		if msgs == None:
			return
		disp_messages(msgs, listbox)
		login_tk.destroy()

def error(message):
	messagebox.showerror("Error", message)

def info(message):
	messagebox.showinfo("Info", message)

def all_messages(username, password):
	resp = str(client.client(HOST, username, password, "ALL"), "utf-8").split("\n")
	if resp[0] != "Success.":
		error(resp[0])
		return None
	lines = []
	for line in resp:
		if line != "":
			lines.append(line)
	if len(lines) < 2:
		return []
	else:
		return lines[1:]

def new_messages(username, password):
	resp = str(client.client(HOST, username, password, "NEW"), "utf-8").split("\n")
	if resp[0] != "Success.":
		error(resp[0])
		return None
	lines = []
	for line in resp:
		if line != "":
			lines.append(line)
	if len(lines) < 2:
		return []
	else:
		return lines[1:]

def load_message(username, password, message):
	resp = str(client.client(HOST, username, password, "RECV\n" + message), "utf-8").split("\n")
	if resp[0] != "Success.":
		error(resp[0])
		return None, None
	if len(resp) < 3:
		error("Server error, invalid protocol")
		return None, None
	return resp[1], "\n".join(resp[2:])

def send_message(username, password, recipients, message):
	resp = str(client.client(HOST, username, password, "SEND\n" + recipients + "\n" + message), "utf-8").split("\n")
	if resp[0] != "Success.":
		error(resp[0])
		return None
	return "success"

def disp_messages(messages, listbox):
	listbox.delete(0, END)
	for i in reversed(messages):
		listbox.insert(END, i)

def disp_new_messages(messages, listbox):
	for i in reversed(messages):
		listbox.insert(0, i)

def refresh(username, password, listbox):
	global LOGGED_IN
	if LOGGED_IN == False:
		return
	msgs = new_messages(username, password)
	if msgs == None:
		return
	disp_new_messages(msgs, listbox)

def view(username, password, listbox):
	for i in listbox.curselection():
		view_single(username, password, listbox, i)
		
def view_single(username, password, listbox, i):
	uuid = listbox.get(i)
	sender, msg = load_message(username, password, uuid)
	if msg == None:
		return
	tk = Toplevel()
	tk.title('KMail Client - ' + uuid)
	label = Label(tk, text="From: " + sender)
	label.pack()
	label2 = Label(tk, text="ID: " + uuid)
	label2.pack()
	textbox = Text(tk, height=15, width=80)
	textbox.pack()
	textbox.insert(END, msg)

def compose(username, password):
	tk = Toplevel()
	tk.title('KMail Client - Compose')
	textbox = Text(tk, height=15, width=80)
	textbox.grid(row=0, column=0)
	recipientsLabel = Label(tk, text="Recipients (seperate with spaces)").grid(row=1, column=0)
	recipients = StringVar()
	recipientsEntry = Entry(tk, textvariable=recipients).grid(row=2, column=0)
	def send(username, password, textbox, recipients):
		msg = textbox.get("1.0", "end-1c")
		recipients = recipients.get()
		if send_message(username, password, recipients, msg) == None:
			# Error, so don't clear the screen.
			pass
		else:
			# Clear the screen.
			tk.destroy()
			info("Sent!")
	compose_button = Button(tk, text="Send", command=lambda: send(username, password, textbox, recipients))
	compose_button.grid(row=3, column=0)

def start_client():
	global USERNAME, PASSWORD
	tk = Tk()
	tk.geometry('300x150')
	tk.title('KMail Client')
	
	scrollbar = Scrollbar(tk)
	scrollbar.pack(side=RIGHT, fill=Y)
	
	listbox = Listbox(tk, yscrollcommand=scrollbar.set)
	listbox.pack(side=LEFT, fill=BOTH)
	scrollbar.config(command=listbox.yview)

	refresh_button = Button(tk, text="Refresh", command=lambda: refresh(USERNAME, PASSWORD, listbox))
	refresh_button.pack(side=LEFT, fill=BOTH)
	view_button = Button(tk, text="Open", command=lambda: view(USERNAME, PASSWORD, listbox))
	view_button.pack(side=LEFT, fill=BOTH)
	compose_button = Button(tk, text="Compose", command=lambda: compose(USERNAME, PASSWORD))
	compose_button.pack(side=LEFT, fill=BOTH)
	refresh_button["state"] = "disabled"
	view_button["state"] = "disabled"
	compose_button["state"] = "disabled"

	login(tk, listbox, refresh_button, view_button, compose_button)

	tk.mainloop()

start_client()