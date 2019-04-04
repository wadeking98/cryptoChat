# Python program to implement client side of chat room. 
import socket 
import select 
import sys 
import re
import sympy
import random
import json

encMode = None
params = None





#------------ mod inv and gcd function courtesy of wikibooks

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m 

def stringToTup(msg):
    msg = msg.strip('#rsa ()\n')
    msg = msg.split(',')
    return tuple(msg)




def isParams(mes):
    return re.search("#(affine|cbc)\s.*",mes)

def isEnc(mes):
    return re.search("#enc\(.*\)", mes)

def getParamsMode(mes):
    return re.search("#(\w+)",mes).group(1)

def getParams(mes):
    return re.search("#(\w+)\s(.*)",mes).group(2)


def getEnc(mes):
    return re.search("#enc\((.*)\)", mes).group(1)


def RSAinit(rang_low, rang_mid, rang_high):
    p = sympy.randprime(rang_low,rang_mid)
    q = sympy.randprime(rang_mid,rang_high)
    
    n = p*q

    phi = (p-1)*(q-1)

    
    b = random.randint(2, phi)
    #make sure gcd of b and phi(n) == 1
    while(egcd(b, phi)[0] != 1):
        b = random.randint(2, phi)
    
    a = modinv(b, phi)

    return ((n,b),(p,q,a))

def RSAdec(rsaMsg, key):
    return pow(int(rsaMsg), int(key[1][2]), int(key[0][0]))

def genSubInv(k):
    return {v:k for k,v in k.items()}

def cbcEk(msg, charPnt, k, IV):
    if(charPnt == 0):
        c = k[ord(msg[0])^IV]
        cyph = chr(c)
        return (c, cyph)
    else:
        e, cyph = cbcEk(msg, charPnt-1, k, IV)
        c = k[ord(msg[charPnt]) ^ e]
        cyph += chr(c)
        return (c, cyph)

def cbcDk(cyph, kinv, IV):
    plntxt = chr(kinv[ord(cyph[0])]^IV)
    
    for i in range(1, len(cyph)):
        p = kinv[ord(cyph[i])]^ord(cyph[i-1])
        plntxt += chr(p)
        
    return plntxt

def affineEnc(params, message):
    cypher = "#enc("
                
    a, b, n = params
    for c in message:
        cypher += (chr((a*ord(c) + b)%n))
    cypher+=")"

    return cypher

    



server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
if len(sys.argv) != 3: 
    print("Correct usage: script, IP address, port number")
    exit() 
IP_address = str(sys.argv[1]) 
Port = int(sys.argv[2]) 
server.connect((IP_address, Port))

#initialise RSA key
key = RSAinit(1000,2000,3000)
kpu = key[0]
kpr = key[1]

#send the public key to the server
server.send(("#rsa "+str(kpu)).encode())

  
while True: 
  
    # maintains a list of possible input streams 
    sockets_list = [sys.stdin, server] 
  
    """ There are two possible input situations. Either the 
    user wants to give  manual input to send to other people, 
    or the server is sending a message  to be printed on the 
    screen. Select returns from sockets_list, the stream that 
    is reader for input. So for example, if the server wants 
    to send a message, then the if condition will hold true 
    below.If the user wants to send a message, the else 
    condition will evaluate as true"""
    read_sockets,write_socket, error_socket = select.select(sockets_list,[],[]) 
  
    for socks in read_sockets: 
        if socks == server:
            #MESSAGE RECIEVED
            message = socks.recv(8192)
            message = message.decode()
            #message is encrypted we have decryption enabled
            if isEnc(message) and encMode:
                #get cyphertext
                addr = message.split(">")[0]
                message = getEnc(message)

                plaintext = ""
                if encMode == "affine":
                    a, b, n = params
                    #calculate the inverse of a
                    ainv = modinv(a, n)

                    #decrypt the message
                    for c in message:
                        chval = (ainv*ord(c) - ainv*b)%n
                        if chval < 0:
                            chval += n
                        plaintext += (chr(chval))
                    print(addr+"> "+plaintext)

                elif encMode == "cbc":
                    IV, k = params
                    kinv = genSubInv(k)

                    plaintext = cbcDk(message, kinv, IV)
                    print(addr+"> "+plaintext)



            elif(isParams(message)):
                print("Cypher updated")
                encMode = getParamsMode(message)
                encParams = json.loads(getParams(message))

                if(encMode == "affine"):
                    params = [RSAdec(int(x), key) for x in encParams]
                elif(encMode == "cbc"):
                    IV = RSAdec(encParams[0], key)
                    k = {RSAdec(ky, key):RSAdec(vl,key) for ky, vl in encParams[1].items()}

                    params = (IV, k)                
            else:
                print(message)
        else: 
            #MESSAGE SENT
            message = sys.stdin.readline() 
            

            message = message.strip('\n')
            
            if(encMode and isEnc(message)):
                message = getEnc(message)
                #apply affine cipher
                if(encMode == "affine"):
                    cypher = affineEnc(params,message)
                    server.send(cypher.encode())
                elif(encMode == "cbc"):
                    IV, k = params
                    c, cypher = cbcEk(message, len(message)-1, k, IV)
                    cypher = "#enc("+cypher+")"
                    server.send(cypher.encode())
            else:
                if("#quit" == message):
                    server.send(message.encode())
                    exit()
                elif("#help" == message):
                    message_to_send ="""+----------+
|CryptoChat|
+----------+

CryptoChat is a cryptography based chat room that allows you to choose
how you encrypt your messages

CryptoChat has RSA encryption built in for key sharing between clients.\n
when you choose a symmetric key cryptosystem the server chooses a key for\n
all the clients and sends it to each of the clients via RSA encryption\n

COMMANDS:

#help | displays this help message

#affine | sets encryption method to affine cypher

#enc(text) | encrypts the text given in the parenthesis
according to the encryption method

#quit | leave the chat room"""
                    print(message_to_send)
                
                else:
                    server.send(message.encode())
                
                
                

            

            
            sys.stdout.flush()

            
server.close() 