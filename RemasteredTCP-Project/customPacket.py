import socket
import sys
import signal
import binascii
import threading
import logging
import time
import random
import os
import matplotlib.pyplot as plt

def test():
    print("hello!")

class tcpPacket:
    def __init__(self,dport):
        self.sport = 0                              # Source Port
        self.dport = dport                          # Destination Port
        self.seqNum = random.randint(0,4294967295)  # Sequence Number
        self.ackNum = 0                             # Acknolwedgment Number
        self.syn = 1                                # SYN 
        self.ack = 0                                # ACK
        self.fin = 0                                # FIN
        self.cwnd = 1                               # Window size (initial size of 1)
        self.header = None                          # No header yet at initialization
        self.savedAcknum = None                     # For seq/ack num verification during data transfer
        self.payload = None                         # No initial payload

    # Getters
    def getSport(self):
        return self.sport
    def getDport(self):
        return self.dport
    def getSeqnum(self):
        return self.seqNum
    def getAcknum(self):
        return self.ackNum
    def getSyn(self):
        return self.syn
    def getAck(self):
        return self.ack
    def getFin(self):
        return self.fin
    def getCwnd(self):
        return self.cwnd
    def getHeader(self):
        return self.header
    def getSavedAcknum(self):
        return self.savedAcknum
    def getPayload(self):
        return self.payload
    
    # Setters
    def setSport(self,input):
        self.sport = input
    def setDport(self,input):
        self.dport = input
    def setSeqnum(self,input):
        self.seqNum = input
    def setAcknum(self,input):
        self.ackNum = input
    def setSyn(self,input):
        self.syn = input
    def setAck(self,input):
        self.ack = input
    def setFin(self,input):
        self.fin = input
    def setCwnd(self,input):
        self.cwnd = input
    def setSavedAcknum(self,input):
        self.savedAcknum = input
    def setPayload(self,input):
        self.payload = input.encode()

    # Make header with current values
    def makeHeader(self):
        self.header = self.sport.to_bytes(2,'big')
        self.header += self.dport.to_bytes(2,'big')
        self.header += self.seqNum.to_bytes(4,'big')
        self.header += self.ackNum.to_bytes(4,'big')
        self.header += self.syn.to_bytes(1,'big')
        self.header += self.ack.to_bytes(1,'big')
        self.header += self.fin.to_bytes(1,'big')
        self.header += self.cwnd.to_bytes(2,'big') 
    
    # Sets self.header = input. For when receiving a header
    def copyHeader(self,input):
        self.header = input
        self.setSport(int(binascii.hexlify(input[0:2]),16))
        self.setDport(int(binascii.hexlify(input[2:4]),16))
        self.setSeqnum(int(binascii.hexlify(input[4:8]),16))
        self.setAcknum(int(binascii.hexlify(input[8:12]),16))
        self.setSyn(int(binascii.hexlify(input[12:13]),16))
        self.setAck(int(binascii.hexlify(input[13:14]),16))
        self.setFin(int(binascii.hexlify(input[14:15]),16))
        self.setCwnd(int(binascii.hexlify(input[15:17]),16))

    # For part 2 of 3-way handshake. Receiver (server) formatting and sending SYN/ACK
    # def makeSYNACKpkt(self,senderPort,receiverPort):
    #     if self.getSyn() == 1:
    #         # Set sport to this senders port
    #         self.setSport(senderPort)
    #         # Set dport to the receivers port 
    #         self.setDport(receiverPort)
    #         # Set ack == 1 (for SYN/ACK, SYN == 1 and ACK == 1)
    #         self.setAck(1)
    #         # 1st. Set acknowledgement number to the seq. num received from packet + 1
    #         self.setAcknum(self.getSeqnum()+1)        
    #         # 2nd. Set sequence number to that of a random integer according to RFC protocols
    #         self.setSeqnum(random.randint(0,4294967295))

    #         # Adjust saved ack num 
    #         self.setSavedAcknum(self.getAcknum())

    #         # Finally, remake header to reflect new values
    #         self.makeHeader()

    # For part 2 of 3-way handshake. Receiver (server) formatting and sending SYN/ACK
    def makeSYNACKpkt(self,senderPort,receiverPort, outPacket):
        if outPacket.getSyn() == 1:
            # Set sport to senders port
            self.setSport(senderPort)
            # Set dport to the receivers port
            self.setDport(receiverPort)
            # Set ack == 1 (for SYN/ACK, SYN == 1 and ACK == 1)
            self.setAck(1); self.setSyn(1)
            # 1st. Set acknowledgement number to the seq. num received from packet + 1
            self.setAcknum(outPacket.getSeqnum()+1)     
            # 2nd. Set sequence number to that of a random integer according to RFC protocols
            self.setSeqnum(random.randint(0,4294967295))
            # Finally, remake header to relfect new values
            self.makeHeader()

    # # Final step of 3-way handshake. Sender formatting and sending back ACK 
    # def makeACKpkt(self):
    #     sport = self.getSport()
    #     dport = self.getDport()
    #     seqNum = self.getSeqnum()
    #     ackNum = self.getAcknum()
    #     self.setSport(dport)
    #     self.setDport(sport)
    #     self.setSeqnum(ackNum)
    #     self.setAcknum(seqNum+1)
    #     self.setSyn(0); self.setAck(1); self.setFin(0)
    #     self.makeHeader()

    #     # Adjust saved ack num
    #     self.setSavedAcknum(self.getAcknum())

    # Final step of 3-way handshake. Sender formatting and sending back ACK 
    def makeACKpkt(self, outPacket):
        # + 1 for the SYN bit that was sent during SYN/ACK 
        self.setSeqnum(self.getSeqnum()+1)
        # If the current seq num does not match the incoming pkts ack num then flag an error
        if self.getSeqnum() != outPacket.getAcknum():
            print("makeACKpkt error!")
        # If the incoming pkt has a SYN, then acknowledge it
        elif outPacket.getSyn() == 1:
            self.setAcknum(outPacket.getSeqnum()+1)
            self.setSyn(0); self.setAck(1)
            self.makeHeader()

    # For adding a data payload to packet
    def addPayload(self):
        self.header += self.payload

    # For deleting the payload from a packet
    def delPayload(self):
        self.header = self.header[0:17]

    # For verification of sequence and acknowledgement numbers
    def verifySeqAck(self, outPacket):   # input may not be neeeded (?)
        if self.getSavedAcknum() != input.getSeqnum():
            print("todo!")

    # For incrementing of sequence and ack nums during communication
    def incrementNums(self):
        print("seq: " + str(self.getSeqnum()))
        print("ack: " + str(self.getAcknum()))

    # For visual and debugging purposes
    def translateHeader(self):
        print("\n** HEADER **")
        print("sport: " + str(self.getSport()))
        print("dport: " + str(self.getDport()))
        print("seqnum: " + str(self.getSeqnum()))
        print("acknum: " + str(self.getAcknum()))
        print("syn: " + str(self.getSyn()))
        print("ack: " + str(self.getAck()))
        print("fin: " + str(self.getFin()))
        print("cwnd: " + str(self.getCwnd())+"\n")
