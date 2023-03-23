from customPacket import *

# Global variable for adjusting max size a packet can be
pktSize = 1000
# Accompanying array that stores said individual packets
packets = []

def getUserInput():
    # Error prevention for user input
    if (len(sys.argv) != 9 or sys.argv[1] != "--server_ip" or 
            sys.argv[3] != "--server_port" or sys.argv[5] != "--tcp_version"
            or sys.argv[7] != "--input"):
        print("usage: python3 tcpSender.py --server_ip XXXX.XXXX.XXXX.XXXX --server_port YYYY --tcp_version tahoe/reno --input input.txt")
        sys.exit(0)
        
    host = str(sys.argv[2])
    port = int(sys.argv[4])
    tcp_version = str(sys.argv[6].lower())
    txt = sys.argv[8]

    # Error prevention for tcp version tahoe/reno input
    if tcp_version != "tahoe".lower() and tcp_version != "reno".lower():
        print("Invalid TCP version entered.")
        print("usage: python3 client_putah.py --server_ip XXXX.XXXX.XXXX.XXXX --server_port YYYY --tcp_version tahoe/reno --input input.txt")
        sys.exit(0)

    # read input.txt file
    with open(txt, "r") as file:
        message = file.read()

    # Will be userinputs[0],userinputs[1],userinputs[2],userinputs[3] respectively
    return (host,port,tcp_version,message)

def start_clientSocket(userinputs):
    # Seperate socketAddress into host,port
    host = userinputs[0]; port = userinputs[1]
    socketAddress = (host,port)

    # Make myPacket to send and fromPacket to receive
    myPacket = tcpPacket(port); fromPacket = tcpPacket(port)
    
    # Create client socket connection to connect with server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cSock:
        
        # Bind socket and save its newly created port number
        cSock.bind( (host,0) )
        cSockPort = cSock.getsockname()[1]

        # Change myPacket sport to new cSockPort and make header to send
        myPacket.setSport(cSockPort)
        myPacket.makeHeader(); myPacket.translateHeader()

        # Initiate 3-way handshake with server's 'welcoming' socket. (send SYN)
        cSock.sendto(myPacket.getHeader(), socketAddress)

        # Receive response from server's 'welcoming' socket. (get SYN/ACK)
        data,addr = cSock.recvfrom(1024)
        fromPacket.copyHeader(data)

        # Prepare packet to be sent back. (send ACK)
        myPacket.makeACKpkt(fromPacket); myPacket.translateHeader()

        # Get new src_port from receivers message.
        sPort = fromPacket.getSport()

        # Finish 3-way handshake. (send ACK)
        cSock.sendto(myPacket.getHeader(), socketAddress)

        # Start new data socket in which all further communication will happen
        start_dataSocket(socketAddress, sPort, addr, fromPacket, userinputs[3])


def start_dataSocket(socketAddress, sPort, addr, myPacket, message):
    # todo
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dSock:
        # (IP,PORT) of receivers' new connection/data transfer socket
        receiver = (addr[0], sPort)

        # Record port of this new data socket. Set packets sPort to this now.
        dSock.bind( (socketAddress[0],0) )
        dSockPort = dSock.getsockname()[1]
        myPacket.setSport(dSockPort); myPacket.makeHeader()

        # Adjust maximum packet size in a msg to account for length of header and payload 
        totalSize = pktSize - len(myPacket.getHeader())

        # Next, split message into packets
        for i in range(0, len(message), totalSize):
            packets.append(message[i:i+totalSize])

        # Create counter variables to keep track of data
        msgLen = len(packets)-1
        pktsLost = 0; pktsSent = 0
        totalBits = 0
        i = 0; k = 0
        transmissionRound = 1; cwndArr = []; transmissionRoundArr = []

        # TESTING

        while i <= len(packets):
            try:
                # Format next message to be sent 
                myPacket.setPayload(packets[i]); myPacket.addPayload()
                dSock.sendto(myPacket.getHeader(),receiver)
                data,addr = dSock.recvfrom(1024)
                print(data)
                myPacket.delPayload()
                i += 1
                
            except:
                print("Successfully finished sending all packets.")
                break

 
# 'Main' Section
start_clientSocket(getUserInput())