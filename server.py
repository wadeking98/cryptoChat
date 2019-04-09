# Python program to implement server side of chat room. 
import socket 
import select 
import sys
import _thread
from _thread import *
import random
import re
import json

mutex = _thread.allocate_lock()

def genSub():
    k = {}

    a = list(range(0,256))
    j = 255

    for i in range(0,256):
        #get a random value from a
        rand = random.randint(0,j)
        #print(rand)
        val = a[rand]

        #remove that value from a
        a.pop(rand)
        j -= 1

        #insert value into dictionary
        k[i] = val
    return k

def genIV():
    return random.randint(0,255)


def RSAenc(rsaMsg, kpu):
    return pow(int(rsaMsg), int(kpu[1]), int(kpu[0]))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def isRSA(msg):
    return re.search("#rsa", msg)

def getRSA(msg):
    return re.search("(?<=#rsa\s).*", msg).group(0)

def stringToTup(msg):
    msg = msg.strip('#rsa ()\n')
    msg = msg.split(',')
    return tuple(msg)

def genAffineKeys(list_of_clients):
    #lock this critical section
    mutex.acquire()
    n = random.randint(126, 255)
    a = random.randint(1, n)
    #make sure a is invertable
    while(egcd(a,n)[0]!=1):
        n = random.randint(126, 255)
        a = random.randint(1,n)

    b = random.randint(1, n)

    print("affine cypher parameters: "+str((a,b,n)))

    for conn in list_of_clients:
        kpu = client_pub_keys[conn]

        package = (RSAenc(a,kpu), RSAenc(b,kpu), RSAenc(n, kpu))
        print("encrypted affine cypher params: "+str(package))

        message_to_send = "#affine "+json.dumps(package)

        conn.send(message_to_send.encode())
    #unlock mutex
    mutex.release()

def genCbcKeys(list_of_clients):
    mutex.acquire()
    k = genSub()
    IV = genIV()


    for conn in list_of_clients:
        kpu = client_pub_keys[conn]

        kenc = {RSAenc(key, kpu):RSAenc(val,kpu) for key, val in k.items()}
        IVenc = RSAenc(IV, kpu)

        package = (IVenc, kenc)
        message_to_send = "#cbc "+json.dumps(package)
        
        conn.send(message_to_send.encode())
    mutex.release()

def genAffineCbcKeys(list_of_clients):
    mutex.acquire()

    n = 255
    a = random.randint(1, n)
    #make sure a is invertable
    while(egcd(a,n)[0]!=1):
        #n = random.randint(126, 255)
        a = random.randint(1,n)

    b = random.randint(1, n)

    k = genSub()
    IV = genIV()

    for conn in list_of_clients:
        kpu = client_pub_keys[conn]

        
        kenc = {RSAenc(key, kpu):RSAenc(val,kpu) for key, val in k.items()}
        IVek = RSAenc(IV, kpu)
        
        package = (RSAenc(a, kpu), RSAenc(b, kpu), RSAenc(n, kpu), IVek, kenc)
        
        message_to_send = "#affinecbc "+json.dumps(package)
        conn.send(message_to_send.encode())

    mutex.release()

  
"""The first argument AF_INET is the address domain of the 
socket. This is used when we have an Internet Domain with 
any two hosts The second argument is the type of socket. 
SOCK_STREAM means that data or characters are read in 
a continuous flow."""
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
  
# checks whether sufficient arguments have been provided 
if len(sys.argv) != 3: 
    print("Correct usage: script, IP address, port number")
    sys.exit(0) 
  
# takes the first argument from command prompt as IP address 
IP_address = str(sys.argv[1]) 
  
# takes second argument from command prompt as port number 
Port = int(sys.argv[2]) 
  
""" 
binds the server to an entered IP address and at the 
specified port number. 
The client must be aware of these parameters 
"""
server.bind((IP_address, Port)) 
  
""" 
listens for 100 active connections. This number can be 
increased as per convenience. 
"""
server.listen(2) 
  
list_of_clients = []

#dictionary of public keys
client_pub_keys = {}
  

def clientthread(conn, addr):
  
    # sends a message to the client whose user object is conn 
    conn.send("Welcome to CryptoChat! type #quit to leave or #help for help".encode())
    message_to_send = "<" + addr[0] + "> has entered the chat"
    broadcast(message_to_send, conn)
  
    while True: 
            try: 
                message = conn.recv(8192) 
                if message: 
                    message = message.decode().strip('\n')
                    """prints the message and address of the 
                    user who just sent the message on the server 
                    terminal"""
                    print("<" + addr[0] + "> " + message)
                    
                    if("#quit" == message):
                        remove(conn)
                        message_to_send = "<" + addr[0] + "> has left the chat"
                        broadcast(message_to_send, conn)
                        break
                        #server ignores #help messages
                    if("#help" == message):
                        pass
                    #get the public key of the client
                    elif(isRSA(message)):
                        kpu = getRSA(message)
                        kpu = stringToTup(message)
                        client_pub_keys.update({conn : kpu})
                    #client has requested keys for affine cypher
                    elif("#affine" == message):
                        genAffineKeys(list_of_clients)
                    
                    elif("#cbc" == message):
                        genCbcKeys(list_of_clients)

                    elif("#affinecbc" == message):
                        genAffineCbcKeys(list_of_clients)

                    elif("#list" == message):
                        conn.send(str(list_of_clients).encode())
                        
                        
                    else:
                        # Calls broadcast function to send message to all 
                        message_to_send = "<" + addr[0] + "> " + message
                        broadcast(message_to_send, conn) 
  
                else: 
                    """message may have no content if the connection 
                    is broken, in this case we remove the connection"""
                    remove(conn) 
  
            except: 
                continue
  
"""Using the below function, we broadcast the message to all 
clients who's object is not the same as the one sending 
the message """
def broadcast(message, connection): 
    for clients in list_of_clients: 
        if clients!=connection: 
            try: 
                clients.send(message.encode()) 
            except: 
                clients.close() 
  
                # if the link is broken, we remove the client 
                remove(clients) 
  
"""The following function simply removes the object 
from the list that was created at the beginning of  
the program"""
def remove(connection): 
    if connection in list_of_clients: 
        list_of_clients.remove(connection) 
        client_pub_keys.pop(connection, None)
  
while True: 
  
    """Accepts a connection request and stores two parameters,  
    conn which is a socket object for that user, and addr  
    which contains the IP address of the client that just  
    connected"""
    conn, addr = server.accept() 
    """Maintains a list of clients for ease of broadcasting 
    a message to all available people in the chatroom"""
    list_of_clients.append(conn)
  
    # prints the address of the user that just connected 
    print(addr[0] + " connected")
  
    # creates and individual thread for every user  
    # that connects 
    start_new_thread(clientthread,(conn,addr))     
  
conn.close() 
server.close() 