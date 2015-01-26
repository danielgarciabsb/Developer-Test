#!/usr/bin/python
# coding: utf-8

# imports
import socket
import sys
import hashlib
import binascii
import collections

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
        print "\n\nPacket Length: %d\n - Bytes: %s\n - Hex: %s" % \
            (sum([ ord(x) for x in self.packetlength ]),
                [ ord(x) for x in self.packetlength ],
                [ x.encode('hex') for x in self.packetlength])
        return self.packetlength

    def __getMD5Sum(self):
        try:
            self.md5sum
        except:
            self.md5sum = self.__receiveBytes(16)
        # Debug
        print "\n\nMD5 Sum: %s\n - Bytes: %s\n - Hex: %s" % \
                (self.md5sum.encode('hex'),
                [ ord(x) for x in self.md5sum ],
                [ x.encode('hex') for x in self.md5sum])
        return self.md5sum

    def __getData(self):
        try:
            self.data
        except:
            self.data = self.__receiveBytes(sum([ ord(x) for x in self.packetlength ]) - 16 - 2 - 1)
        # Debug
        print "\n\nData: %s\n - Bytes: %s\n - Hex: %s" % \
                (self.data.encode('hex'),
                [ ord(x) for x in self.data ],
                [ x.encode('hex') for x in self.data])
        return self.data

    def __getParityByte(self):
        try:
            self.parity
        except:
            self.parity = self.__receiveBytes(1)
        # Debug
        print "\n\nParity: %s\n - Bytes: %s\n - Hex: %s" % \
                (self.parity.encode('hex'),
                [ ord(x) for x in self.parity ],
                [ x.encode('hex') for x in self.parity])
        return self.parity

    def __checkMessageParity(self, bits):
        
        num_1bits = bits.count('1')

        # Check if parity byte exists
        if(int(bits[len(bits)-8:]) > 1):
            print "Parity byte does not exists!"
        else:
            if(bits[:len(bits)-8].count('1') % 2 == 0):
                print "Message number of 1 bits is Even (%d), checking parity byte..." % bits[:len(bits)-8].count('1')
                print "Parity byte is %s" % bits[len(bits)-8:]
            else:
                print "Message number of 1 bits is ODD (%d), checking parity byte..." % bits[:len(bits)-8].count('1')
                print "Parity byte is %s" % bits[len(bits)-8:]
        
        if(num_1bits % 2 == 0):
            print "Even number of 1 bits (%d), message parity is ok" % num_1bits
            return 0
        else:
            print "Odd number of 1 bits (%d), message parity is not ok" % num_1bits
            return 1

    def __checkDataMD5Sum(self):
        newmd5 = hashlib.md5()
        newmd5.update(self.data)
        md5sum = newmd5.hexdigest()
        if(md5sum == self.md5sum.encode('hex')):
            print "Data MD5 sum is OK %s == %s" %  (self.md5sum.encode('hex'), md5sum)
        else:
            print "Data MD5 sum is NOT ok %s != %s" % (self.md5sum.encode('hex'), md5sum)

    def __getMostCommonByte(self):
        counts = collections.Counter([ x.encode('hex') for x in self.data]).most_common()
        self.mostcommonbyte = counts[0][0]
        print "Most commom byte in data is hex: %s" % self.mostcommonbyte
        return self.mostcommonbyte

    def __getCipherKey(self):
        self.cipherkey = int(self.mostcommonbyte,16) ^ 0x20
        print "Cipherkey: Int: %s - Hex: %s" % (self.cipherkey, hex(self.cipherkey)[2:])
        return self.cipherkey

    def __decodeData(self):
        mdata = [ x.encode('hex') for x in self.data ]
        self.decodedmessage = [ chr(int(x,16) ^ self.cipherkey) for x in mdata ]
        print self.decodedmessage
        print "Decoded data hex: %s" % [ x.encode('hex') for x in self.decodedmessage]
        self.decodedmessage = ''.join(self.decodedmessage)
        print "\nDecoded data str: %s" % self.decodedmessage
        return self.decodedmessage

    def __createDecodedMessage(self):

        nm_length = 2 + 16 + len(self.decodedmessage) + 1
        hexnmlength = hex(nm_length)[2:]
        print "\nNM length: %d - Hex: %s" % (nm_length, hexnmlength)
        message_length = [hexnmlength[i:i+2] for i in range(0, len(hexnmlength), 2)]
        
        # Miau por falta de conhecimento como adicionar 0's em 2 bytes hex no python
        if(nm_length <= 0xff):
            print 'True'
            zb = ['00']
            zb.extend(message_length)
            nm_length = zb
            print nm_length
        else:
            nm_length = message_length
        # Fim do Miau

        nm_newmd5 = hashlib.md5()
        nm_newmd5.update(self.decodedmessage)
        md5sum = nm_newmd5.hexdigest()

        print "\nNM decoded data MD5 sum: %s" % md5sum
        nm_md5sum = [md5sum[i:i+2] for i in range(0, len(md5sum), 2)]
        print nm_md5sum

        nm_decodedmessage = [ x.encode('hex') for x in self.decodedmessage]

        nm_parity = 0x0

        nm_message = []
        nm_message.extend(nm_length)
        nm_message.extend(nm_md5sum)
        nm_message.extend(nm_decodedmessage)

        print "NM message: "
        print nm_message

        nm_binary = (bin(int(''.join(nm_message), 16))[2:]).zfill(len(''.join(nm_message)) * 4)

        print "\nNM binary: %s" % nm_binary

        nm_parity = self.__checkMessageParity(nm_binary)

        nm_parity = [nm_parity]
        nm_parity = [''.join('{:02x}'.format(x) for x in nm_parity)]
        nm_message.extend(nm_parity)

        # Recheck message parity
        nm_binary = (bin(int(''.join(nm_message), 16))[2:]).zfill(len(''.join(nm_message)) * 4)        
        nm_parity = self.__checkMessageParity(nm_binary)

        print "\nNM binary: %s" % nm_binary

        print "NM message: "
        print nm_message

        self.nm_message = ''.join(nm_message)

        print "NM message str: %s" % self.nm_message

    def getEncryptedMessage(self):
        print "Client: Receiving new message..."
        self.__getPacketLength()
        self.__getMD5Sum()
        self.__getData()
        self.__getParityByte()

        self.message = self.packetlength + self.md5sum + self.data + self.parity
        
        binarymessage = (bin(int(self.message.encode('hex'), 16))[2:]).zfill(len(self.message.encode('hex')) * 4)
        
        print "\n\nMessage: %s\n - Hex: %s\n - Bin: %s" % \
                ([ ord(x) for x in self.message ],
                    self.message.encode('hex'),
                    binarymessage)

        self.__checkMessageParity(binarymessage)
        self.__checkDataMD5Sum()

        self.__getMostCommonByte()
        self.__getCipherKey()
        self.__decodeData()

    def sendDecodedMessage(self):
        print "Client: Creating decoded message..."
        self.__createDecodedMessage()
        print "Client: Sending decoded message..."
        self.client.send(self.nm_message.decode('hex'))

    def getServerResponse(self):
        pass

    def connect(self, address, port):
        try:
            self.client.connect((address, port))
        except socket.error, e:
            print >> sys.stderr, e
            self.client.close()
            sys.exit()

    def disconnect(self):
        self.client.close()