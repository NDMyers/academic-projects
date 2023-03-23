from customPacket import *

def signal_handler(signal,frame):
    print("exiting")
    sys.exit(0)

def getUserInput():
    host = str(sys.argv[1])
    port = int(sys.argv[2])
    return (host,port)

def start_dataSocket(dSock):
    myPacket = tcpPacket(0) # Placeholder 0 for initialization. Will be replaced 
    while True:
        try:
            # Receive data from sender
            data,addr = dSock.recvfrom(1024)  
            myPacket.copyHeader(data)

            # If the received data contains a FIN, send back ACK then close connection
            if myPacket.getFin() == 1:
                print("todo!")

            # Check how many bits sent at once for BDP

            # Get payload from received packet

            # Adjust sequence/acknowledgement numbers

            # Send ACK back to receiver
            dSock.sendto("Received!".encode(),addr)

        except socket.timeout:
            print("\nError ocurred. 'data' socket disconnected.")

def start_welcomeSocket(socketAddress):
    # Parse out address into individual variables
    host = socketAddress[0]; port = socketAddress[1]

    # Create 'welcoming' socket 
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wSocket:

        # Create packet variables to be used throughout. 
        myPacket = tcpPacket(port); outPacket = tcpPacket(port)

        # Bind socket and get its newly created port number
        wSocket.bind(socketAddress)      # <-- can use (socketAddress) or (host,port). Same idea
        wSocketPort = wSocket.getsockname()[1]

        while True:
            try:
                # Take part in three-way handshake. (get SYN)
                data,addr = wSocket.recvfrom(1024)
                receiverPort = addr[1]
                outPacket.copyHeader(data)

                # Set and bind new data socket 
                dSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dSock.bind( (host,0) )

                # Record new port to send to client so they can connect to it
                dSockPort = dSock.getsockname()[1]

                # Copy in header to tcpPacket(), reformat and change necessary values
                myPacket.makeSYNACKpkt(dSockPort,receiverPort,outPacket); myPacket.translateHeader()

                # Send response to sender's socket. (send SYN/ACK)
                wSocket.sendto(myPacket.getHeader(),addr)

                # Receive response from sender. (get ACK)
                data,addr = wSocket.recvfrom(1024)
                myPacket.copyHeader(data); outPacket.copyHeader(data)

                # If 3-way successful. Start new thread for data socket for concurrent running sockets
                if outPacket.getAck() == 1:
                    dThread = threading.Thread(target=start_dataSocket,args=(dSock,))
                    dThread.start()
                
            except:
                print("\nError ocurred. 'Welcoming' socket disconnected.")
                break

def main():
    # Variable consisting of (host,port)
    socketAddress = getUserInput()

    # Threading to allow for multi-client connections 
    sockThread = threading.Thread(target=start_welcomeSocket,args=(socketAddress,))
    sockThread.start()

if __name__ == "__main__":
    main()