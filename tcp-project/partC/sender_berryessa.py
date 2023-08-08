import socket
import sys
import binascii
import time
import random
import logging
import matplotlib.pyplot as plt

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

def logFormatWithCWND(packet,logger,cwnd,state):
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
    cwnd = str(cwnd)
    logString = str(source + " | " + destination + " | " + msgType + " | " + cwnd + " | " + state + " | " + msgLength)
    logger.info(logString)


# END OF LOG FORMATTING

PKT_SIZE = 1000
packets = []

def create_message(message_id, message):
    # return the message
    return f"#{message_id}@ {message}"

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
    elif desiredFlag=="synack":
        return (int(binascii.hexlify(syn)), int(binascii.hexlify(ack)))
    elif desiredFlag=="cwnd":
        return int(binascii.hexlify(cwnd),16)

def parseSynAck(packet):
    synack = parsePacket(packet,"synack")
    if synack[0]==1 and synack[1]==1:
        seqnum = packet[8:12]
        seqnum = (int(binascii.hexlify(seqnum),16) + 1).to_bytes(4,'big')
        ackNum = packet[4:8]    # this packets acknum set to received packet's seqnum
        newSlice = b'\x00\x01\x00'
        packet = packet[2:4] + packet[0:2] + seqnum + ackNum + newSlice + packet[15:]
    return packet

def makeFinMsg(packet):
    dport = parsePacket(packet,'dport')
    dport = dport.to_bytes(2,'big')
    syn=0;ack=0;fin=1

    # placeholder sequm and acknum
    seqnum = 0; acknum = 0

    packet = packet[0:2] + dport + seqnum.to_bytes(4,'big') + acknum.to_bytes(4,'big')
    packet += syn.to_bytes(1,'big')
    packet += ack.to_bytes(1,'big')
    packet += fin.to_bytes(1,'big')
    return packet

def makePacketWithData(packet, data):
    packet = packet[:17] + data.encode()
    #newsport = port.to_bytes(2,'big')
    #return newsport + packet[2:] + data.encode()
    return packet

def parseDataPacket(packet):
    data = packet[17:]
    return data.decode()

def get_seqackNums_in_ints(packet):
    seqnum = int(binascii.hexlify(packet[4:8]),16)
    acknum = int(binascii.hexlify(packet[8:12]),16)
    return seqnum,acknum

def set_sport(packet,port):
    newsport = port.to_bytes(2,'big')
    adjusted_packet = newsport + packet[2:]
    return adjusted_packet

def set_dport(packet,port):
    newdport = port.to_bytes(2,'big')
    adjusted_packet = packet[0:2] + newdport + packet[4:]
    return adjusted_packet

def adjust_seqackNum(packet,numbits):
    cur_seqnum = int(binascii.hexlify(packet[4:8]),16)
    cur_acknum = int(binascii.hexlify(packet[8:12]),16)
    new_seqnum = (cur_seqnum+numbits).to_bytes(4,'big')
    adjusted_packet = packet[:4] + new_seqnum + packet[8:]
    return adjusted_packet

def flip_seqackNum(packet):
    adjusted_packet = packet[:4] + packet[8:12] + packet[4:8] + packet[12:]
    return adjusted_packet

def adjustCWND(packet, isCongestion):
    if isCongestion==0:
        cwnd = int(binascii.hexlify(packet[15:17]),16)
        new_cwnd = (2*cwnd).to_bytes(2,'big')
        #print("new_cwnd in adjustCWDN():",new_cwnd)
        packet = packet[0:15] + new_cwnd + packet[17:]
        return packet
    elif isCongestion==1:
        new_cwnd = 1
        packet = packet[0:15] + new_cwnd.to_bytes(2,'big') + packet[17:]
        return packet

def adjustCWND_with_GLOBAL(packet, globalCWND):
    return packet[0:15] + globalCWND.to_bytes(2,'big') + packet[17:]


# Get arguments 
if (len(sys.argv) != 9 or sys.argv[1] != "--server_ip" or sys.argv[3] != "--server_port" or sys.argv[5] != "--tcp_version" or sys.argv[7] != "--input"):
    print("usage: python3 client_putah.py --server_ip XXXX.XXXX.XXXX.XXXX --server_port YYYY --tcp_version tahoe/reno --input input.txt")
    sys.exit(0)
HOST = sys.argv[2]
PORT = int(sys.argv[4])
TCP_VERSION = str(sys.argv[6]).lower()
TXT = sys.argv[8]
IS_TAHOE = 0
IS_RENO = 0
STARTING_SSTH = 16
INITIAL_CWND = 1

if TCP_VERSION != "tahoe".lower() and TCP_VERSION != "reno".lower():
    print("Invalid TCP version entered.")
    print("usage: python3 client_putah.py --server_ip XXXX.XXXX.XXXX.XXXX --server_port YYYY --tcp_version tahoe/reno --input input.txt")
    sys.exit(0)

if TCP_VERSION == "tahoe":
    IS_TAHOE = 1
elif TCP_VERSION == "reno":
    IS_RENO = 1
# read input.txt file
with open(TXT, "r") as file:
    message = file.read()

# =============== HEADER STRUCTURE =================
# Source Port | Destination Port
# Sequence Number
# Acknowledgement Number
# Data Offset, Reserved, Flags | Window Size
# Checksum | Urgent Pointer

# Create 'TCP' header variables. More barebones for this project
sport = 0                                   # Source Port
dport = PORT                                # Destination Port
seqNum = random.randint(0,4294967295)
ackNum = 0 
syn = 1                                     # SYN
ack = 0                                     # ACK
fin = 0                                     # FIN
cwnd = 1                                    # Window size (initial size == 1)

header = sport.to_bytes(2,'big')
header += dport.to_bytes(2,'big')
header += seqNum.to_bytes(4,'big')
header += ackNum.to_bytes(4,'big')
header += syn.to_bytes(1,'big')
header += ack.to_bytes(1,'big')
header += fin.to_bytes(1,'big')
header += cwnd.to_bytes(2,'big')

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

        # port of THIS new client socket. Set packets SPORT to this instead.
        sock2.bind( (HOST,0) )
        newPort = sock2.getsockname()[1]
        ack = set_sport(ack,newPort)

        # Create totalSize that a packet should be 
        totalSize = PKT_SIZE-len(ack)

        # split the message into packets
        for i in range(0, len(message), totalSize):
            packets.append(message[i:i+totalSize])

        # Counter variables 
        msgLen = len(packets)-1
        i = 0
        k = 0   
        packetsLost = 0
        packetsSent = 0
        totalBits = 0
        transmissionRound = 1
        cwndArray = []
        transmissionRoundArray = []

        # string that tells if it is in slow start or congestion avoidance
        current_state = ""

        # INITIAL MESSAGE WHILE LOOP
        while True:
            try:
                sock2.settimeout(1)
                current_state = "SLOW START"

                # make/send initial msg
                initialMsg = adjust_seqackNum(ack,1000)
                initialMsg = makePacketWithData(initialMsg,packets[0])
                
                # Store sequence number to check if correct ACK is received
                storeSeqNum = get_seqackNums_in_ints(initialMsg)[0]

                # Set timers for timeout intervals
                startTime = time.time()
                totalTimeStart = time.time()

                # Send initialMsg to receiver and log
                sock2.sendto(initialMsg, receiver)
                logFormatWithCWND(initialMsg,logger,INITIAL_CWND,current_state)
                cwndArray.append(INITIAL_CWND)
                transmissionRoundArray.append(transmissionRound)

                # Get ACK back from receiver and end time for timeout interval
                acknowledgement,addr = sock2.recvfrom(1024)
                endTime = time.time()

                # Check if ACK corresponds to our sent data
                verify = get_seqackNums_in_ints(acknowledgement) # (seqnum, acknum)

                # If it is correct ACK, then continue on
                if storeSeqNum == verify[1]:    # if old ACKnum == new SEQnum, then good      

                    # 1. Creates sampleRTT for timeout interval calculation and sets timeout  
                    sampleRTT = endTime-startTime
                    estimatedRTT = sampleRTT
                    devRTT = sampleRTT/2
                    timeoutInterval = estimatedRTT + (4*devRTT)
                    sock2.settimeout(timeoutInterval)

                    # 2. Increment packets sent and readjust acknowledgement for rest of the packets to be sent
                    packetsSent += 1
                    startingPacket = flip_seqackNum(acknowledgement)
                    
                    # 3. Adjust CWND for startingPacket
                    startingPacket = adjustCWND(startingPacket,0)
                    INITIAL_CWND = 1

                    # Increment how many bits we have sent so far for later calculations and break
                    bits_sent_so_far = len(initialMsg)
                    break

                # If it incorrect ACK, then something is wrong. Resend
                elif storeSeqNum != verify[1]: # Jitter case
                    packetsLost += 1

            # If timeout, increment packets lost and resend
            except socket.timeout:
                packetsLost += 1

        k += 1
        transmissionRound += 1
        eofCounter = 0

        # Boolean that checks if ssth has already halved or not
        hasDivided = 0
        dupeAck = 0

        # Make all remaining messages
        messages = []
        for j in range(len(packets)-1):
            newMsg = makePacketWithData(startingPacket,packets[j+1])
            bits_sent_so_far += len(newMsg)
            newMsg = adjust_seqackNum(newMsg,bits_sent_so_far)
            messages.append(newMsg)

        # Acknowledgements array and has_sent array
        acknowledgements = [False for message in messages]
        packNum = 0
        has_sent = [False for message in messages]


        # Next while loop which processes rest of the data
        while True:

            try:

                # i stands for packet #. if i reaches the last packet, then we stop sending since we have finished
                if eofCounter >= msgLen:
                    fin = makeFinMsg(startingPacket)
                    sock2.sendto(fin,addr)
                    logFormat(fin,logger)
                    data,addr = sock2.recvfrom(1024)
                    if parsePacket(data,"ack")==1:
                        print("\nACK received from server:", data,addr)     
                        print("Closing socket.")
                        sock2.close()
                    break

                # Readjust timeout according to RFC and set it
                if timeoutInterval < 1:
                    timeoutInterval = 1
                sock2.settimeout(timeoutInterval)

                # Append CWND/TransmissionRoundArrays for graph
                cwndArray.append(INITIAL_CWND)
                transmissionRoundArray.append(transmissionRound)
                transmissionRound += 1

                # SSTH AND CWND ADJUSTMENT AREA
                # SLOW START (double cwnd)
                if INITIAL_CWND < STARTING_SSTH:
                    current_state = "SLOW START"
                    INITIAL_CWND *= 2
                    hasDivided = 0

                # AIMD and if SLOW START reaches SSTH. Once threshhold reached, increment by 1
                elif INITIAL_CWND >= STARTING_SSTH:
                    current_state = "CONGESTION AVOIDANCE"
                    if hasDivided == 0:
                        STARTING_SSTH //= 2
                        hasDivided = 1
                    INITIAL_CWND += 1

                # Sliding Window Sending 
                if packNum+INITIAL_CWND < len(packets):
                    for j in range(packNum,packNum+INITIAL_CWND):
                        
                        # Can send it if it has not been sent already
                        if has_sent[j] == False:
                            dupeAck = 0
                            # Create messages to be sent and send them
                            messages[j] = adjustCWND_with_GLOBAL(messages[j],INITIAL_CWND)
                            startTime = time.time()
                            sock2.sendto(messages[j],receiver)

                            # Receive ACK
                            acknowledgement,addr = sock2.recvfrom(1024)
                            endTime = time.time()
                            if acknowledgement not in acknowledgements:
                                acknowledgements[packNum] = True

                            # Mark as sent and increment variables. Log
                            has_sent[j] = True
                            eofCounter += 1
                            logFormatWithCWND(messages[j],logger,INITIAL_CWND,current_state)

                        # Increment packNum 
                        if acknowledgements[packNum] == True:
                            packNum += 1
                            startTime = time.time()

                # Same as above sliding window, but for packets that could not be processed due to out of range bc of adding INITIAL_CWND
                if packNum+INITIAL_CWND > len(packets) and packNum < len(packets):
                    for j in range(packNum,len(packets)-1):

                        # Can send it if it has not been sent already
                        if has_sent[j] == False:
                            dupeAck = 0
                            # Create messages to be sent and send them
                            messages[j] = adjustCWND_with_GLOBAL(messages[j],INITIAL_CWND)
                            startTime = time.time()
                            sock2.sendto(messages[j],receiver)

                            # Receive ACK
                            acknowledgement,addr = sock2.recvfrom(1024)
                            endTime = time.time()
                            if acknowledgement not in acknowledgements:
                                acknowledgements[packNum] = True

                            # Mark as sent and log
                            has_sent[j] = True
                            eofCounter += 1
                            logFormatWithCWND(messages[j],logger,INITIAL_CWND,current_state)    
                        
                        # Increment packNum
                        if acknowledgements[packNum] == True:
                            packNum += 1
                            startTime = time.time()                    

                # Recalculate timeout interval
                sampleRTT = endTime - startTime
                estimatedRTT = (0.0875 * estimatedRTT) + (0.125 * sampleRTT)
                devRTT = (0.75 * devRTT) + (0.25 * (abs(sampleRTT-estimatedRTT)))
                timeoutInterval = estimatedRTT + (4*devRTT)

                # Increment counter variables
                i+=INITIAL_CWND
                k+=INITIAL_CWND
                packetsSent += INITIAL_CWND

            
            except socket.timeout:
                # If timeout occurs, resend the messages
                packetsLost += 1
                if IS_TAHOE:
                    STARTING_SSTH = INITIAL_CWND//2
                    INITIAL_CWND = 1
                elif IS_RENO:
                    INITIAL_CWND //= 2
                    STARTING_SSTH = INITIAL_CWND
                print(f"Timeout for packet # {k}, resending")

            # If interrupt, send fin and close once ACK is received
            except KeyboardInterrupt:
                fin = makeFinMsg(startingPacket)
                sock2.sendto(fin,addr)
                logFormat(fin,logger)
                data,addr = sock2.recvfrom(1024)
                if parsePacket(data,"ack")==1:
                    print("\nACK received from server:", data,addr)     
                    print("Closing socket.")
                    sock2.close()
                    break

totalTimeEnd = time.time()

# CWND/TRANSMISSION array graph
plt.plot(transmissionRoundArray, cwndArray, color='green', linestyle='dashed', linewidth = 3,
         marker='o', markerfacecolor='blue', markersize=10)
plt.xlabel('Transmission Round')
plt.ylabel('CWND - in segments')
plt.show()


# Calculate measurements after all is finished
totalTimeTaken = totalTimeEnd-totalTimeStart
print("Total time taken for file transfer:", totalTimeTaken)

totalBandwidth = (bits_sent_so_far) / totalTimeTaken
print("Total bandwidth for this file:", totalBandwidth,"bps")

totalPacketLoss = packetsLost/packetsSent
print("Total packet loss observed for this file:", totalPacketLoss)
