import socket
import sys
import binascii
import time
import logging

# LOG FORMATTING
logger = logging.getLogger()
logging.getLogger().handlers
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
    source = str(parsePacket(packet,'sport'))
    destination = str(parsePacket(packet,'dport'))
    syn = parsePacket(packet, 'syn')
    ack = parsePacket(packet, 'ack')
    fin = parsePacket(packet, 'fin')
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
    logString = str(source + " | " + destination + " | " + msgType + " | " + msgLength)
    logger.info(logString)

# END OF LOG FORMATTING

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
    elif desiredFlag=="synack":
        return (int(binascii.hexlify(syn)), int(binascii.hexlify(ack)))

def parseSynAck(packet):
    synack = parsePacket(packet,"synack")
    if synack[0]==1 and synack[1]==1:
        newSlice = b'\x00\x01\x00'
        packet = packet[2:4] + packet[0:2] + newSlice
    return packet

def makeFinMsg(packet):
    dport = parsePacket(packet,'dport')
    dport = dport.to_bytes(2,'big')
    syn=0;ack=0;fin=1

    packet = packet[0:2] + dport
    packet += syn.to_bytes(1,'big')
    packet += ack.to_bytes(1,'big')
    packet += fin.to_bytes(1,'big')
    return packet

def makePacketWithData(packet):
    data = "Ping".encode()
    packet += data
    print(packet)
    return packet

def parseDataPacket(packet):
    data = packet[7:]
    return data.decode()

def set_sport(packet,port):
    newsport = port.to_bytes(2,'big')
    adjusted_packet = newsport + packet[2:]
    return adjusted_packet

def set_dport(packet,port):
    newdport = port.to_bytes(2,'big')
    adjusted_packet = packet[0:2] + newdport + packet[4:]
    return adjusted_packet

def makeAck(packet):
    sport=packet[2:4]
    dport=packet[0:2]
    syn=0;ack=1;fin=0

    header = sport + dport
    header += syn.to_bytes(1,'big')
    header += ack.to_bytes(1,'big')
    header += fin.to_bytes(1,'big')
    return header

# Get arguments 
if (len(sys.argv) != 5 or sys.argv[1] != "--server_ip" or sys.argv[3] != "--server_port"):
    print("usage: python3 client_putah.py --server_ip XXXX.XXXX.XXXX.XXXX --server_port YYYY")
    sys.exit(0)
HOST = sys.argv[2]
PORT = int(sys.argv[4])

# =============== HEADER STRUCTURE =================
# Source Port | Destination Port
# Sequence Number
# Acknowledgement Number
# Data Offset, Reserved, Flags | Window Size
# Checksum | Urgent Pointer

# Create 'TCP' header variables. More barebones for this project
sport = 0                                   # Source Port
dport = PORT                                # Destination Port
syn = 1                                     # SYN
ack = 0                                     # ACK
fin = 0                                     # FIN

header = sport.to_bytes(2,'big')
header += dport.to_bytes(2,'big')
header += syn.to_bytes(1,'big')
header += ack.to_bytes(1,'big')
header += fin.to_bytes(1,'big')

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock1:

    # Bind socket and get port
    sock1.bind( (HOST, 0) )
    sock1Port = sock1.getsockname()[1]

    # Change initial header to reflect sock1's random sport
    header = set_sport(header, sock1Port)

    # Send SYN and log it
    sock1.sendto(header, (HOST, PORT))  # SYN SENDING
    logFormat(header,logger)
    data,addr = sock1.recvfrom(1024)    # SYN/ACK + data received

    # Get new src_port from receiver
    newsport = parsePacket(data,'sport')

    # ack has actual data for program, logAck has more consistent src/dst ports for readability in log
    ack = parseSynAck(data)
    logAck = set_dport(ack,addr[1])

    # Send ACK and log it
    sock1.sendto(ack, (HOST, PORT))  # ACK SENT
    logFormat(logAck,logger)

    # Make new client socket for data transfer
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock2: 

        # (IP, PORT) of receivers' new connection socket
        receiver = (addr[0],newsport)

        # Port of THIS new client socket. Set packets SPORT to this instead
        sock2.bind( (HOST,0) ) 
        sock2Port = sock2.getsockname()[1]
        ack = set_sport(ack,sock2Port)

        # Create "Pong" Message to be sent endlessly
        msg = makePacketWithData(ack)

        while True:

            try:
                # Set timeout
                sock2.settimeout(1)

                # Send "Ping" message to receiver
                sock2.sendto(msg, receiver)
                logFormat(msg,logger)

                # Receive message from sender
                data,addr = sock2.recvfrom(1024)

                # If the received data is a FIN, send back ACK then close connection
                if parsePacket(data,"fin")==1:
                    acknowledgement = makeAck(data)
                    sock2.sendto(acknowledgement,addr)
                    logFormat(acknowledgement,logger)
                    print("FIN received. ACK sent & closing socket.")
                    sock2.close()
                    break

            except socket.timeout:
                print("Timeout occurred...")

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
