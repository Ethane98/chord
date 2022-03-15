import socket
import threading
import sys
import json
import hashlib

#Basic node info:
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

#Add Node
#This is the root node:
if predecessor_port == 0:
	predecessor = node
	successor = node
	for i in range(m):
		finger_table[i] = node
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
	for i in range(m):
		search = ((node[0] + (2**i)) % (2**m)) 
		print ("Finger ", i, ": ", search)
		if (search <= node[0] and search > predecessor[0]) or (search <= node[0] and predecessor[0] >= node[0]) or (search > predecessor[0] and predecessor[0] >= node[0]):
			print ("Return: ", node[0])
			finger_table[i] = node
		else: 
			stmp = socket.socket()
			stmp.connect(('127.0.0.1', successor[1]))
			request = json.dumps({"type": 5, "search": search})
			stmp.send(request.encode())
			response = stmp.recv(1024)
			response = json.loads(response.decode())
			stmp.close()
			print ("Return: ", response.get("id"))
			finger_table[i] = response.get("id")
		
	#Notify predecessors to update their finger tables
	stmp = socket.socket()
	stmp.connect(('127.0.0.1', predecessor[1]))
	request = json.dumps({"type": 4, "updated": node})
	stmp.send(request.encode())
	stmp.close()


#Request protocol:
#Request type int 1-9

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

#6 Request: Notify a predecessor that a node is being removed, contains predecessor/node/successor of removed node
#6 Response: N/A

#7 Request: Notify a successor that a node is being removed, contains predecessor and files to take over
#7 Response: N/A

#8 Request: Update finger table given a node (predecessor + successor included) being removed
#8 Response: N/A

#9 Request: Check if a given has belongs to the node (Check Successor)
#9 Response: True or False


def run():
	global predecessor;
	global successor;
	
	while True:
		#Connect/receive incoming requests
		c, addr = s.accept()
		print ("Connected to", addr)
		request = c.recv(1024)
		request = json.loads(request.decode())
		request_type = request.get("type")
		print ("Request type: ", request_type)
		
		#Handle incoming requests:
		
		#Notify Predecessor Add
		if request_type == 0:
			#Update own successor and return old successor
			request_node = request.get("node")
			response = json.dumps({"node": [node[0], node[1]], "successor": [successor[0], successor[1]]})
			c.send(response.encode())
			successor = request_node
			
		#Notify Successor Add
		if request_type == 1:
			request_node = request.get("node")
			predecessor = request_node
			tmpfiles = {}
			#Give up files belonging to the new node and return them
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
			#Check if file is owned by current node
			if file_hash in files.keys():
				response = json.dumps({"string": files[file_hash]})
			#Check if file ought to be owned by node but not found
			elif (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				response = json.dumps({"string": "File not found"})
			#Forward either with circular search or finger table search
			else:
				#Ask successor if it ought to have the file
				print("Checking successor")
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 9, "search": file_hash})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				#Forward request to successor
				if response.get("value") == True:
					print("Forwarding request to find file")
					stmp = socket.socket()
					stmp.connect(('127.0.0.1', successor[1]))
					forward = json.dumps({"type": 2, "hash": file_hash})
					stmp.send(forward.encode())
					response = stmp.recv(1024).decode()
					stmp.close()
				#Forward to the greatest finger table entry less than the file hash
				else:
					for i in range(m):
						if (finger_table[m-i-1][0] >= node[0] and file_hash >= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] <= node[0] and file_hash <= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] >= node[0] and file_hash <= node[0]):
							print("Forwarding request to find file")
							stmp = socket.socket()
							stmp.connect(('127.0.0.1', finger_table[m-i-1][1]))
							forward = json.dumps({"type": 2, "hash": file_hash})
							stmp.send(forward.encode())
							response = stmp.recv(1024).decode()
							stmp.close()
							break

			c.send(response.encode())
		#Store
		if request_type == 3:
			file_hash = request.get("hash")
			file_string = request.get("string")
			#Check if file ought to be owned by current node, if so store
			if (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				files[file_hash] = file_string
			#Forward either with circular search or finger table search
			else:
				#Ask successor if it ought to own the file
				print("Checking successor")
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 9, "search": file_hash})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				#Forward request to the successor
				if response.get("value") == True:
					print("Forwarding request to store file")
					stmp = socket.socket()
					stmp.connect(('127.0.0.1', successor[1]))
					forward = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
					stmp.send(forward.encode())
					stmp.close()
				#Forward request to highest finger table entry less than the file hash
				else:
					for i in range(m):
						if (finger_table[m-i-1][0] >= node[0] and file_hash >= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] <= node[0] and file_hash <= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] >= node[0] and file_hash <= node[0]):
							print("Forwarding request to store file")
							stmp = socket.socket()
							stmp.connect(('127.0.0.1', finger_table[m-i-1][1]))
							forward = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
							stmp.send(forward.encode())
							stmp.close()
							break
				
		#Update Finger Tables Add
		if request_type == 4:
			request_node = request.get("updated")
			#Update finger table: if added node ought to own finger table entry key, replace entry
			for i in range(m):
				search = ((node[0] + (2**i)) % (2**m)) 
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', request_node[1]))
				forward = json.dumps({"type": 9, "search": search})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				if response.get("value") == True:
					print("Replace finger table entry")
					finger_table[i] = request_node
				stmp.close()
				
			#Forward update request to predecessor, stop when we reach full circle	
			if request_node[0] != predecessor[0]:
				print("Forward request to update finger tables")
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', predecessor[1]))
				forward = json.dumps({"type": 4, "updated": request_node})
				stmp.send(forward.encode())
				stmp.close()
				
		#Get Successor
		if request_type == 5:
			response = ''
			search = request.get("search")
			
			#If search hash id ought to be owned by node, return node
			if (search <= node[0] and search >= predecessor[0]) or (search <= node[0] and predecessor[0] >= node[0]) or (search >= predecessor[0] and predecessor[0] >= node[0]):
				response = json.dumps({"id": node})
			#Forward GetSuccessor to either circular search or finger table search
			else:
				#Ask successor if it ought to own hash value
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 9, "search": search})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				
				#Return successor id
				if response.get("value") == True:
					response = json.dumps({"id": successor})
				#Forward request to highest finger table entry less than the hash value
				else:
					for i in range(m):
						if (finger_table[m-i-1][0] >= node[0] and search >= node[0] and finger_table[m-i-1][0] < search) or (finger_table[m-i-1][0] <= node[0] and search <= node[0] and finger_table[m-i-1][0] < search) or (finger_table[m-i-1][0] >= node[0] and search <= node[0]):
							print("Forwarding request to get successor")
							stmp = socket.socket()
							stmp.connect(('127.0.0.1', finger_table[m-i-1][1]))
							forward = json.dumps({"type": 5, "search": search})
							stmp.send(forward.encode())
							response = stmp.recv(1024).decode()
							stmp.close()
							break
			
			c.send(response.encode())
			
		#Notify Predecessor Remove
		if request_type == 6:
			#Replace own successor with removed node's successor
			request_node = request.get("takeover_node")
			successor = request_node
			
			#Forward update finger table request to predecessor
			stmp = socket.socket()
			stmp.connect(('127.0.0.1', predecessor[1]))
			request = json.dumps({"type": 8, "takeover_node": request_node, "node": request.get("node"), "stop_node": request.get("stop_node")})
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
			#Update finger table: if removed node is in the finger table, replace with its successor
			for i in range(m):
				search = ((node[0] + (2**i)) % (2**m)) 
				if request.get("node")[0] == finger_table[i][0]:
					print("Replacing finger table entry")
					finger_table[i] = request.get("takeover_node")
				
			#Stop when we reach full circle
			if request.get("stop_node")[0] != node[0]:
				print("Forwarding request to update finger tables")
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', predecessor[1]))
				request = json.dumps({"type": 8, "takeover_node": request.get("takeover_node"), "node": request.get("node"), "stop_node": request.get("stop_node")})
				stmp.send(request.encode())
				stmp.close()
			
		#Helper: Check if hash belongs to node
		if request_type == 9:
			search = request.get("search")
			print("Received query if hash belongs to this node")
			#If hash belongs to node, return true; else false
			if (search <= node[0] and search > predecessor[0]) or (search <= node[0] and predecessor[0] >= node[0]) or (search > predecessor[0] and predecessor[0] >= node[0]):
				response = json.dumps({"value": True})
			else:
				response = json.dumps({"value": False})

			c.send(response.encode())
			
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
			for i in range(m):
				print ("Entry ", ((node[0] + (2**i)) % (2**m)), ":  Node ", finger_table[i][0],": Port ", finger_table[i][1])
		
		if interact_input == "2":
			file_string = input("Enter file string\n")
			file_hash = hashlib.sha1(file_string.encode()).hexdigest()
			file_hash = (int(file_hash, 16)) % (2**m)
			if (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				files[file_hash] = file_string
				
			#Forward either with circular search or finger table search
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 9, "search": file_hash})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				if response.get("value") == True:
					stmp = socket.socket()
					stmp.connect(('127.0.0.1', successor[1]))
					forward = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
					stmp.send(forward.encode())
					stmp.close()
				else:
					for i in range(m):
						if (finger_table[m-i-1][0] >= node[0] and file_hash >= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] <= node[0] and file_hash <= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] >= node[0] and file_hash <= node[0]):
							stmp = socket.socket()
							stmp.connect(('127.0.0.1', finger_table[m-i-1][1]))
							forward = json.dumps({"type": 3, "hash": file_hash, "string": file_string})
							stmp.send(forward.encode())
							stmp.close()
							break
			print ("File hashed: ", file_hash)
			
		if interact_input == "3":
			file_hash = int(input("Enter file hash\n"))
			
			if file_hash in files.keys():
				print ("File string: ", files[file_hash])
			elif (file_hash <= node[0] and file_hash > predecessor[0]) or (file_hash <= node[0] and predecessor[0] >= node[0]) or (file_hash > predecessor[0] and predecessor[0] >= node[0]):
				print ("File string: File not found")
			#Forward either with circular search or finger table search
			else:
				stmp = socket.socket()
				stmp.connect(('127.0.0.1', successor[1]))
				forward = json.dumps({"type": 9, "search": file_hash})
				stmp.send(forward.encode())
				response = stmp.recv(1024)
				response = json.loads(response.decode())
				stmp.close()
				if response.get("value") == True:
					stmp = socket.socket()
					stmp.connect(('127.0.0.1', successor[1]))
					forward = json.dumps({"type": 2, "hash": file_hash})
					stmp.send(forward.encode())
					response = stmp.recv(1024)
					stmp.close()
				else:
					for i in range(m):
						if (finger_table[m-i-1][0] >= node[0] and file_hash >= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] <= node[0] and file_hash <= node[0] and finger_table[m-i-1][0] < file_hash) or (finger_table[m-i-1][0] >= node[0] and file_hash <= node[0]):
							stmp = socket.socket()
							stmp.connect(('127.0.0.1', finger_table[m-i-1][1]))
							forward = json.dumps({"type": 2, "hash": file_hash})
							stmp.send(forward.encode())
							response = stmp.recv(1024)
							stmp.close()
							break
				response = json.loads(response.decode())
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
			request = json.dumps({"type": 6, "takeover_node": successor, "node": node, "stop_node": predecessor})
			stmp.send(request.encode())
			stmp.close()
			
			s.close()
			exit()
			
interact_thread = threading.Thread(target=interact)
interact_thread.start()

run()
