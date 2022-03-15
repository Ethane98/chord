import socket
import threading
import sys
import json
import hashlib

#Node info:
m = 8

predecessor = [0, 0]
successor = [0, 0]

finger_table = [[0] * 2] * m

files = {}

node = (int(sys.argv[1]), int(sys.argv[2]))
if node[0] > 2**m:
	exit()
	
predecessor_port = int(sys.argv[3])

#Setup listening socket:
s = socket.socket()
print ("Socket created")

s.bind(('', node[1]))
print ("Socket bound to %s" %(node[1]))

s.listen(0)

#Request protocol:
#Request type int:
#0: Update successor and get successor information
#1: Update predecessor

#0 Request: Add node
#Port: int Port to be set as successor
#ID: int ID to be set as successor
#0 Response:
#Successor port: int
#Successor ID: int

#1 Request: Update predecessor
#Predecessor port: int port to be set as predecessor
#Predecessor ID: int ID to be set as predecessor
#1 Response: N/A

#2 Request: Find file
#File hash: hash to be searched
#2 Response:
#File string: File content returned

#3 Request: Add file
#File hash: hash to be stored
#File string: file content to be stored
#3 Response: N/A

#4 Request: Update finger table
#4 Response: N/A

#5 Request: Get successor given a hash key
#5 Response: Node ID that is responsible for hash

#Add()
#This is the root node:
if predecessor_port == 0:
	predecessor = node
	successor = node
	finger_table[0] = successor
else:
	#Get info from user-specified predecessor and update its successor
	stmp = socket.socket()
	stmp.connect(('127.0.0.1', predecessor_port))
	request = json.dumps({"type": 0, "node": [node[0], node[1]]})
	stmp.send(request.encode())
	response = stmp.recv(1024)
	response = json.loads(response.decode())
	successor = response.get("successor")
	predecessor = response.get("node")
	stmp.close()
	
	#Update new successor's predecessor and get files
	stmp = socket.socket()
	stmp.connect(('127.0.0.1', successor[1]))
	request = json.dumps({"type": 1, "node": [node[0], node[1]]})
	stmp.send(request.encode())
	response = stmp.recv(1024)
	response = json.loads(response.decode())
	tmpfiles = response.get("files")
	for item in list(tmpfiles):
		files[int(item)] = tmpfiles[item]
	stmp.close()
	
	#Update finger table
	stmp = socket.socket()
	stmp.connect(('127.0.0.1', predecessor[1]))
	request = json.dumps({"type": 4, "updated": node[0]})
	stmp.send(request.encode())
	stmp.close()

def run():
	global predecessor;
	global successor;
	
	while True:
		c, addr = s.accept()
		print ("Connected to", addr)
		request = c.recv(1024)
		request = json.loads(request.decode())
		request_type = request.get("type")
	
		print ("Request type: ", request_type)
		#Notify Predecessor Add
		if request_type == 0:
			request_node = request.get("node")
			response = json.dumps({"node": [node[0], node[1]], "successor": [successor[0], successor[1]]})
			c.send(response.encode())
			successor = request_node
		#Notify Successor Add
		if request_type == 1:
			request_node = request.get("node")
			predecessor = request_node
			tmpfiles = {}
			for file_hash in list(files):
				if file_hash <= request_node[0]:
					tmpfiles[file_hash] = files[file_hash]
					del files[file_hash]
			response = json.dumps({"files": tmpfiles})
			c.send(response.encode())

		#Find
		if request_type == 2:
			file_hash = request.get("hash")
			response = ''
			if file_hash in files.keys():
				response = json.dumps({"string": files[file_hash]})
			elif (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				response = json.dumps({"string": "File not found"})
			#Forward either with circular search or finger table search
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 2, "hash": file_hash})
				stmp.send(forward.encode())
				response = stmp.recv(1024).decode()
				stmp.close()

			print("Relayed find file request")
			c.send(response.encode())
		#Store
		if request_type == 3:
			file_hash = request.get("hash")
			file_string = request.get("string")
			if (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				files[file_hash] = file_string
			#Forward either with circular search or finger table search
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
				stmp.send(forward.encode())
				stmp.close()
		#Update Finger Tables Add
		if request_type == 4:
			if request.get("updated") != predecessor[0]:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', predecessor[1]))
				request = json.dumps({"type": 4, "updated": request.get("updated")})
				stmp.send(request.encode())
				stmp.close()
		#Get Successor
		if request_type == 5:
			response = ''
			search = request.get("search")
			if (search <= node[0] and file_hash > predecessor[0]) or (search <= node[0] and predecessor[0] >= node[0]) or (search > predecessor[0] and predecessor[0] >= node[0]):
				response = json.dumps({"id": node[0]})
			#Forward GetSuccessor to either circular search or finger table search
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 5, "search": search})
				stmp.send(forward.encode())
				stmp.close()
			c.send(response.encode())
			
		#Notify Predecessor Remove
		if request_type == 6:
			request_node = request.get("node")
			successor = request_node
			stmp = socket.socket()
			stmp.connect(('127.0.0.1', predecessor[1]))
			request = json.dumps({"type": 8, "updated": node[0]})
			stmp.send(request.encode())
			stmp.close()
			
		#Notify Successor Remove
		if request_type == 7:
			request_node = request.get("node")
			predecessor = request_node
			tmpfiles = request.get("files")
			for f in list(tmpfiles):
				files[int(f)] = tmpfiles[f]
			
		#Update Finger Tables Remove
		if request_type == 8:
			if request.get("updated") != predecessor[0]:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', predecessor[1]))
				request = json.dumps({"type": 8, "updated": request.get("updated")})
				stmp.send(request.encode())
				stmp.close()
			
		c.close()

def interact():
	global predecessor;
	global successor;
	
	while True:
		interact_input = input("\n----------------\n1. Print node info\n2. Submit file\n3. Search for file\n4. Exit (Remove node)\n")
		if interact_input == "1":
			print ("Printing node info")
			print ("Self: ", node[0], " ", node[1])
			print ("Successor: ", successor[0], " ", successor[1])
			print ("Predecessor: ", predecessor[0], " ", predecessor[1])
			for key, value in files.items():
				print ("File ", key, ": ", value)
			print ("Finger table: ")
			for entry in finger_table:
				print (entry[0],": ", entry[1])
		
		if interact_input == "2":
			file_string = input("Enter file string\n")
			file_hash = hashlib.sha1(file_string.encode()).hexdigest()
			file_hash = (int(file_hash, 16)) % (2**m)
			if (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				files[file_hash] = file_string
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				request = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
				stmp.send(request.encode())
				stmp.close()
			print ("File hashed: ", file_hash)
			
		if interact_input == "3":
			file_hash = int(input("Enter file hash\n"))
			
			if file_hash in files.keys():
				print ("File string: ", files[file_hash])
			elif (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				print ("File string: File not found")
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				request = json.dumps({"type": 2, "hash": file_hash})
				stmp.send(request.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				file_string = response.get("string")
				print ("File string: ", file_string)
		
		if interact_input == "4":
			stmp = socket.socket()
			stmp.connect(('127.0.0.1', successor[1]))
			request = json.dumps({"type": 7, "node": predecessor, "files": files})
			stmp.send(request.encode())
			stmp.close()
			
			stmp = socket.socket()
			stmp.connect(('127.0.0.1', predecessor[1]))
			request = json.dumps({"type": 6, "node": successor})
			stmp.send(request.encode())
			stmp.close()
			
			s.close()
			exit()
			
interact_thread = threading.Thread(target=interact)
interact_thread.start()

run()





