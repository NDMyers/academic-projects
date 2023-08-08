import socket
import sys
import binascii
import threading
import logging
import time
import random
import os

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

# Get arguments
if (len(sys.argv) != 11 or sys.argv[1] != "--ip" or sys.argv[3] != "--port" or sys.argv[5] != "--packet_loss_percentage" or sys.argv[7] != "--round_trip_jitter" or sys.argv[9] != "--output"):
    print("usage: python3 server_putah.py --ip XXXX.XXXX.XXXX.XXXX --port YYYY --packet_loss_percentage X --round_trip_jitter Y --output output.txt")
    sys.exit(0)
HOST = str(sys.argv[2])
PORT = int(sys.argv[4])
PACKET_LOSS_PERCENTAGE = int(sys.argv[6])
JITTER = int(sys.argv[8])
OUTPUT = str(sys.argv[10])

outputFile = open(OUTPUT, 'w')

def create_acknowledgement(message_id):
    # return the acknowledgement
    return f"{message_id}$ Acknowledged"

def parsePacket(packet,desiredFlag):
    sport = packet[0:2]
    dport = packet[2:4]
    seqnum = packet[4:8]
    acknum = packet[8:12]
    syn = packet[12:13]
    ack = packet[13:14]
    fin = packet[14:15]
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
        #sport = PORT.to_bytes(2,'big')
        sport = addr.to_bytes(2,'big')
        #seqnum = packet[4:8]
        receivedseqnum = packet[4:8]
        seqnum = random.randint(0,4294967295).to_bytes(4,'big')
        #newdport = addr.to_bytes(2,'big')
        newdport = senderAddr.to_bytes(2,'big')
        #ackNum = int(binascii.hexlify(seqnum),16) + 1
        ackNum = receivedseqnum
        newSlice = b'\x01\x01\x00'      # sets SYN and ACK == 1
        packet = sport + newdport + seqnum + ackNum + newSlice
    print(get_seqackNums_in_ints(packet))
    return packet

def parseAck(packet):
    ack = parsePacket(packet,"ack")
    if ack==1:
        receivedseqnum = packet[4:8]
        acknum = receivedseqnum
        seqnum = packet[8:12]
        newSlice = b'\x00\x01\x00'
        packet = packet[2:4] + packet[0:2] + seqnum + acknum + newSlice
    print(get_seqackNums_in_ints(packet))
    return packet, 1

def makeAck(packet):
    sport=packet[2:4]
    dport=packet[0:2]

    #placeholder seqnum/acknum
    seqnum = 0; acknum = 0
    
    syn=0;ack=1;fin=0

    header = sport + dport
    header += seqnum.to_bytes(4,'big')
    header += acknum.to_bytes(4,'big')
    header += syn.to_bytes(1,'big')
    header += ack.to_bytes(1,'big')
    header += fin.to_bytes(1,'big')
    return header

def parseDataPacket(packet):
    data = packet[15:]
    return data.decode()

def makeDataPacket(packet):
    data = "Pong".encode()
    packet = packet[:15] + data
    return packet

def adjust_seqackNum(packet, bits_sent_so_far):
    # print('here')
    cur_seqnum = int(binascii.hexlify(packet[4:8]),16)
    cur_acknum = int(binascii.hexlify(packet[8:12]),16)
    new_seqnum = (cur_acknum+bits_sent_so_far).to_bytes(4,'big')
    new_acknum = (cur_seqnum).to_bytes(4,'big')
    #print("new_acknum:",new_acknum)
    adjusted_packet = packet[2:4] + packet[0:2] + new_seqnum + new_acknum + packet[12:15]
    # adjusted_packet = packet[:8] + new_acknum + packet[12:15] 
    #print(adjusted_packet,'\n')
    return adjusted_packet

def get_seqackNums_in_ints(packet):
    seqnum = int(binascii.hexlify(packet[4:8]),16)
    acknum = int(binascii.hexlify(packet[8:12]),16)
    return seqnum,acknum

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

def connectionSocket(sock2):

    k=0
    z=0 # makes directory/file path creation happen once

    # Set timeout cap
    timeouts = 0

    while True:
        sock2.settimeout(1)
        try:
            
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

            # Subdirectory creation for specific ports for output.txt
            port = str(addr[1])
            if z == 0:
                directory = './'+port+"/"
                filepath = os.path.join(directory, OUTPUT)
                if not os.path.isdir(directory):
                    os.mkdir(directory)
                outputFile = open(filepath,'w') 
                z = 1

            # Gets payload from packet
            parseddata = parseDataPacket(data)

            # Randomly drop or jitter the packet
            random_chance = random.randint(0,100)
            if random_chance < PACKET_LOSS_PERCENTAGE:
                continue
            elif random_chance > JITTER:
                time.sleep(random_chance/100)

            # Adjust seqnum/acknum
            timeouts = 0 
            adjusted_packet = adjust_seqackNum(data,k)

            # Write to output.txt file
            outputFile.write(parseddata)

            # Send ACK back to sender and log
            sock2.sendto(adjusted_packet, addr)
            logFormat(adjusted_packet,logger)

            k += 1  

        except socket.timeout:
            print('Timeout occurred...')
            # timeouts += 1
            # #print(timeouts)
            # if timeouts > 7:
            #     print("No further input. Client disconnected.")
            #     break

            if parsePacket(data,"fin")==1:
                acknowledgement = makeAck(data)
                sock2.sendto(acknowledgement,addr)
                logFormat(acknowledgement,logger)
                print("FIN received. ACK sent & closing socket.")
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
