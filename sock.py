#!/usr/bin/python
# coding: utf-8

# imports
import socket
import sys

# classes

class SockClient(object):
    """SockClient for handling the connection to the server"""
    def __init__(self):
        # Creates a TCP/IP socket
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, e:
            print >> sys.stderr, e
            sys.exit()

    def connect(self, address, port):
        try:
            self.client.connect((address, port))
        except socket.error, e:
            print >> sys.stderr, e
            self.client.close()
            sys.exit()

    def __receiveBytes(self, amount):
        try:
            received = self.client.recv(amount)
        except socket.error, e:
            print >> sys.stderr, e
            self.client.close()
            sys.exit()
        # Debug
        print "\nReceived: %d" % len(received)
        return received

    def __getPacketLength(self):
        try:
            self.packetlength
        except:
            self.packetlength = self.__receiveBytes(2)
        # Debug
        print "\n\nPacket Length: %d\n - Bytes: %s\n - String: %s\n - Hex: %s" % \
            (sum([ ord(x) for x in self.packetlength ]),
                [ ord(x) for x in self.packetlength ],
                self.packetlength.encode('hex'),
                [ x.encode('hex') for x in self.packetlength])
        return self.packetlength

    def __getMD5Sum(self):
        try:
            self.md5sum
        except:
            self.md5sum = self.__receiveBytes(16)
        # Debug
        print "\n\nMD5 Sum: %s\n - Bytes: %s\n - String: %s\n - Hex: %s" % \
                (self.md5sum.encode('hex'),
                [ ord(x) for x in self.md5sum ],
                self.md5sum.encode('hex'),
                [ x.encode('hex') for x in self.md5sum])
        return self.md5sum

    def __getDataAndParity(self):
        try:
            self.data
        except:
            self.data = self.__receiveBytes(sum([ ord(x) for x in self.packetlength ]) - 16 - 2)
        # Debug
        print "\n\nData: %s\n - Bytes: %s\n - String: %s\n - Hex: %s" % \
                (self.data.encode('hex'),
                [ ord(x) for x in self.data ],
                self.data.encode('hex'),
                [ x.encode('hex') for x in self.data])
        return self.data

    def __checkMessageParity(self):
        pass

    def getMessage(self):
        self.__getPacketLength()
        self.__getMD5Sum()
        self.__getDataAndParity()
        self.__checkMessageParity()

        self.message = self.packetlength + self.md5sum + self.data
        bmsize = len(self.message.encode('hex')) * 4
        binarymessage = (bin(int(self.message.encode('hex'), 16))[2:]).zfill(bmsize)
        print "\n\nMessage: %s\n - Hex: %s\n - Bin: %s\n - Count 1s: %d" % \
                ([ ord(x) for x in self.message ],
                    self.message.encode('hex'),
                    binarymessage,
                    binarymessage.count('1'))

    def disconnect(self):
        self.client.close()

