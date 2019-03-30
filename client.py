# Python program to implement client side of chat room. 
import socket 
import select 
import sys 
import re

encMode = None


#------------ AFFINE CIPHER
a = None
b = None


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



def isCommand(mes):
    return re.search("#set", mes)

def isEnc(mes):
    return re.search("#enc\(.*\)", mes)

def getMode(mes):
    return re.search("(?<=#set\s)\w+", mes).group(0)

def getTag(mes, tag):
    pat = "(?<=#set\s).*-a\s(\w+)"
    return re.search("(?<=#set\s).*-"+tag+"\s(\w+)", mes).group(1)

def getEnc(mes):
    return re.search("#enc\((.*)\)", mes).group(1)



server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
if len(sys.argv) != 3: 
    print("Correct usage: script, IP address, port number")
    exit() 
IP_address = str(sys.argv[1]) 
Port = int(sys.argv[2]) 
server.connect((IP_address, Port)) 
  
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
            message = socks.recv(2048)
            message = message.decode()
            #message is encrypted we have decryption enabled
            if isEnc(message) and encMode:
                #get cyphertext
                addr = message.split(">")[0]
                message = getEnc(message)

                plaintext = ""
                if encMode == "affine":
                    #calculate the inverse of a
                    ainv = modinv(a, 126)

                    #decrypt the message
                    for c in message:
                        chval = (ainv*ord(c) - ainv*b)%126
                        if chval < 0:
                            chval += 126
                        plaintext += (chr(chval))
                    print(addr+">"+plaintext)
            else:
                print(message)
        else: 
            message = sys.stdin.readline() 
            

            message = message.strip('\n')

            #------- set encryption params -------------

            #determine the encryption mode before sending
            #don't send the set encryption parameters command to the
            #server for security reasons
            if(isCommand(message)):
                encMode = getMode(message)
                if(encMode=="affine"):
                    a = int(getTag(message, 'a'))
                    b = int(getTag(message, 'b'))


            #-------- apply encryption ----------------
                
            else:
                #if encryption mode is set and message is not
                #plaintext
                if(encMode and isEnc(message)):
                    message = getEnc(message)
                    cypher = "#enc("
                    #apply affine cipher
                    if(encMode == "affine"):
                        for c in message:
                            cypher += (chr((a*ord(c) + b)%126))
                        cypher+=")"
                        server.send(cypher.encode())
                else:
                    server.send(message.encode())
                    if("#quit" == message):
                        exit()
                    
                

            

            
            sys.stdout.flush()

            
server.close() 