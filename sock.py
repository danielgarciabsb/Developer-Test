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
        self.connected = True

    def receiveBytes(self, amount):
        if self.connected == True:
            try:
                received = self.client.recv(amount)
            except socket.error, e:
                print >> sys.stderr, e
                self.client.close()
                sys.exit()
            return received
        else:
            raise Exception("Error: The socket is not connected")
        return None

    def getPacketLength(self):
        return self.receiveBytes(2)

    def getMD5Sum(self):
        return self.receiveBytes(16)

    def disconnect(self):
        self.client.close()

