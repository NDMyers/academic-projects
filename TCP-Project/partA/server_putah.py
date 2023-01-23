import socket
import sys
import binascii
import threading
import logging


# LOG FORMATTING

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s | %(asctime)s')

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

file_handler = logging.FileHandler('logs.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stdout_handler)

def logFormat(packet, logger):
    #print("in here")
    source = str(parsePacket(packet,'sport'))
    destination = str(parsePacket(packet,'dport'))
    syn = parsePacket(packet, 'syn')
    ack = parsePacket(packet, 'ack')
    fin = parsePacket(packet, 'fin')
    #print(syn, ack)
    if syn == 1 and ack == 1:
        msgType = "SYN/ACK"
    elif syn == 1:
        msgType = "SYN"
    elif ack == 1:
        msgType = "ACK"
    elif fin == 1:
        msgType = "FIN"
    if len(parseDataPacket(packet)) > 0:
        msgType = "DATA"
    msgLength = str(len(packet))
    #print(msgType)
    logString = str(source + " | " + destination + " | " + msgType + " | " + msgLength)
    logger.info(logString)

# END OF LOG FORMATTING

# Get arguments
if (len(sys.argv) != 5 or sys.argv[1] != "--ip" or sys.argv[3] != "--port"):
    print("usage: python3 server_putah.py --ip XXXX.XXXX.XXXX.XXXX --port YYYY")
    sys.exit(0)
HOST = str(sys.argv[2])
PORT = int(sys.argv[4])

def parsePacket(packet,desiredFlag):
    sport = packet[0:2]
    dport = packet[2:4]
    syn = packet[4:5]
    ack = packet[5:6]
    fin = packet[6:7]
    if desiredFlag=="sport":
        return int(binascii.hexlify(sport),16)
    elif desiredFlag=="dport":
        return int(binascii.hexlify(dport),16)
    elif desiredFlag=="syn":
        return int(binascii.hexlify(syn))
    elif desiredFlag=="ack":
        return int(binascii.hexlify(ack))
    elif desiredFlag=="fin":
        return int(binascii.hexlify(fin))

def parseSyn(packet,addr,senderAddr):
    syn = parsePacket(packet,"syn")
    if syn==1:
        sport = addr.to_bytes(2,'big')
        newdport = senderAddr.to_bytes(2,'big')
        newSlice = b'\x01\x01\x00'
        packet = sport + newdport + newSlice
    return packet


def parseAck(packet):
    ack = parsePacket(packet,"ack")
    if ack==1:
        newSlice = b'\x00\x01\x00'
        packet = packet[2:4] + packet[0:2] + newSlice
    return packet, 1

def makeAck(packet):
    sport=packet[2:4]
    dport=packet[0:2]
    syn=0;ack=1;fin=0

    header = sport + dport
    header += syn.to_bytes(1,'big')
    header += ack.to_bytes(1,'big')
    header += fin.to_bytes(1,'big')
    return header

def makeDataPacket(packet):
    data = "Pong".encode()
    packet = packet[2:4] + packet[0:2] + packet[4:7] + data
    return packet

def parseDataPacket(packet):
    data = packet[7:]
    return data.decode()

def makeFinMsg(packet):
    dport = parsePacket(packet,'dport')
    dport = dport.to_bytes(2,'big')
    syn=0;ack=0;fin=1

    packet = packet[0:2] + dport
    packet += syn.to_bytes(1,'big')
    packet += ack.to_bytes(1,'big')
    packet += fin.to_bytes(1,'big')
    return packet

def connectionSocket(sock2):

    while True:

        try:
            # Set timeout
            sock2.settimeout(1)
            timeouts = 0
            
            # Receive data from sender
            data,addr = sock2.recvfrom(1024)

            # If the received data is a FIN, send back ACK then close connection
            if parsePacket(data,"fin")==1:
                acknowledgement = makeAck(data)
                sock2.sendto(acknowledgement,addr)
                logFormat(acknowledgement,logger)
                print("FIN received. ACK sent & closing socket.")
                sock2.close()
                break

            # Make packet to send back
            msg = makeDataPacket(data)

            # Send ACK back to sender and log
            sock2.sendto(msg, addr)
            logFormat(msg, logger)

        except socket.timeout:
            print('Timeout occurred...')
            timeouts += 1
            if timeouts > 7:
                print("No further input. Client disconnected.")
                break

            if parsePacket(data,"fin")==1:
                acknowledgement = makeAck(data)
                sock2.sendto(acknowledgement,addr)
                logFormat(acknowledgement,logger)
                print("FIN received. ACK sent & closing socket.")
                sock2.close()
                break

        except KeyboardInterrupt:
            fin = makeFinMsg(msg)
            sock2.sendto(fin, addr)
            logFormat(fin,logger)
            data,addr = sock2.recvfrom(1024)
            if parsePacket(data,"ack")==1:
                print("\nACK received from server:", data,addr)     
                print("Closing socket.")
                sock2.close()
                break


def welcomeSocket(addr):

    HOST = addr[0]; PORT = addr[1]

    # Create welcoming socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock1:    

        # Bind socket and get port
        sock1.bind((HOST,PORT))
        sock1Port = sock1.getsockname()[1]

        while True:
            
            try:

                # Receive SYN from sender
                data,addr = sock1.recvfrom(1024)

                # Set and bind new socket for Connection Socket 
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
                sock2.bind( (HOST,0) )

                # Retrieve new port to send to sender, so that they can connect to connection socket 
                newPort = (sock2.getsockname()[1])

                # Send SYN/ACK to sender with new port information as well
                synAckPacket = parseSyn(data,newPort,addr[1])
                logPacket = parseSyn(data,sock1Port,addr[1])
                logFormat(logPacket,logger)
                sock1.sendto(synAckPacket,addr)             # SYN/ACK SENDING

                # Receive ACK from sender
                data,addr = sock1.recvfrom(1024)            # ACK RECEIVED
                ack = parseAck(data)

                # Start connection socket thread
                if ack[1]==1:
                    t2 = threading.Thread(target=connectionSocket, args=(sock2,))   # start connection socket thread
                    t2.start()

            except:
                print("error, welcome client disconnected")
                continue



addr = (HOST,PORT)

t1 = threading.Thread(target=welcomeSocket, args=(addr,)) 
t1.start()