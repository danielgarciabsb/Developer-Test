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
        packetlength = self.__receiveBytes(2)
        # Debug
        print "\n\nPacket Length: %d\n - Bytes: %s\n - Hex: %s" % \
            (int(''.join([ x.encode('hex') for x in packetlength ]),16),
                [ ord(x) for x in packetlength ],
                [ x.encode('hex') for x in packetlength])

        return packetlength

    def __getMD5Sum(self):
        md5sum = self.__receiveBytes(16)
        # Debug
        print "\n\nMD5 Sum: %s\n - Bytes: %s\n - Hex: %s" % \
                (md5sum.encode('hex'),
                [ ord(x) for x in md5sum ],
                [ x.encode('hex') for x in md5sum])
        return md5sum

    def __getData(self, amount):
        data = self.__receiveBytes(amount)
        # Debug
        print "\n\nData: %s\n - Bytes: %s\n - Hex: %s" % \
                (data.encode('hex'),
                [ ord(x) for x in data ],
                [ x.encode('hex') for x in data])
        return data

    def __getParityByte(self):
        parity = self.__receiveBytes(1)
        # Debug
        print "\n\nParity: %s\n - Bytes: %s\n - Hex: %s" % \
                (parity.encode('hex'),
                [ ord(x) for x in parity ],
                [ x.encode('hex') for x in parity])
        return parity

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

    def __checkDataMD5Sum(self, data, message_md5):
        newmd5 = hashlib.md5()
        newmd5.update(data)
        md5sum = newmd5.hexdigest()
        if(md5sum == message_md5):
            print "Data MD5 sum is OK %s == %s" %  (message_md5, md5sum)
        else:
            print "Data MD5 sum is NOT ok %s != %s" % (message_md5, md5sum)

    def __getMostCommonByte(self, data):
        counts = collections.Counter([ x.encode('hex') for x in data]).most_common()
        self.mostcommonbyte = counts[0][0]
        print "Most commom byte in data is hex: %s" % self.mostcommonbyte

    def __getCipherKey(self):
        self.cipherkey = int(self.mostcommonbyte,16) ^ 0x20
        print "Cipherkey: Int: %s - Hex: %s" % (self.cipherkey, hex(self.cipherkey)[2:])

    def __decodeData(self, data):
        mdata = [ x.encode('hex') for x in data ]
        decodedmessage = [ chr(int(x,16) ^ self.cipherkey) for x in mdata ]
        print decodedmessage
        print "Decoded data hex: %s" % [ x.encode('hex') for x in decodedmessage]
        decodedmessage = ''.join(decodedmessage)
        print "\nDecoded data str: %s" % decodedmessage
        return decodedmessage

    def __createDecodedMessagePacket(self, decodedmessage):

        nm_length = 2 + 16 + len(decodedmessage) + 1
        hexnmlength = hex(nm_length)[2:]
	if (len(hexnmlength) == 3):
            hexnmlength = '0'+hexnmlength
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
        nm_newmd5.update(decodedmessage)
        md5sum = nm_newmd5.hexdigest()

        print "\nNM decoded data MD5 sum: %s" % md5sum
        nm_md5sum = [md5sum[i:i+2] for i in range(0, len(md5sum), 2)]
        print nm_md5sum

        nm_decodedmessage = [ x.encode('hex') for x in decodedmessage]

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

        createdmessage = ''.join(nm_message)

        print "NM message str: %s" % createdmessage

        return createdmessage

    def getEncryptedMessage(self):
        print "Client: Receiving new message..."
        packetlength = self.__getPacketLength()
        md5sum       = self.__getMD5Sum()
        data         = self.__getData(int(''.join([ x.encode('hex') for x in packetlength ]),16) - 16 - 2 - 1)
        parity       = self.__getParityByte()

        message = packetlength + md5sum + data + parity
        
        binarymessage = (bin(int(message.encode('hex'), 16))[2:]).zfill(len(message.encode('hex')) * 4)
        
        print "\n\nMessage: %s\n - Hex: %s\n - Bin: %s" % \
                ([ ord(x) for x in message ],
                    message.encode('hex'),
                    binarymessage)

        self.__checkMessageParity(binarymessage)
        self.__checkDataMD5Sum(data, md5sum.encode('hex'))
        self.__getMostCommonByte(data)
        self.__getCipherKey()

        return data

    def getDecodedMessage(self, encryptedMessagedata):
        decodedmessage = self.__decodeData(encryptedMessagedata)
        return decodedmessage

    def sendDecodedMessage(self, decodedmessage):
        print "Client: Creating decoded message..."
        createdmessage = self.__createDecodedMessagePacket(decodedmessage)
        print "Client: Sending decoded message..."
        try:
            self.client.send(createdmessage.decode('hex'))
        except socket.error, e:
            print "Error sending decoded data: %s" % e
            sys.exit(1)
        print "Client: Decoded message has been successfully sent!"

    def getServerResponse(self):
        print "Client: Getting server response..."
        
	packetlength = self.__getPacketLength()
        md5sum       = self.__getMD5Sum()
        data         = self.__getData(int(''.join([ x.encode('hex') for x in packetlength ]),16) - 16 - 2 - 1)
        parity       = self.__getParityByte()

        message = packetlength + md5sum + data + parity
        
        binarymessage = (bin(int(message.encode('hex'), 16))[2:]).zfill(len(message.encode('hex')) * 4)
        
        print "\n\nMessage: %s\n - Hex: %s\n - Bin: %s" % \
                ([ ord(x) for x in message ],
                    message.encode('hex'),
                    binarymessage)

        self.__checkMessageParity(binarymessage)
        self.__checkDataMD5Sum(data, md5sum.encode('hex'))

        return data

    def connect(self, address, port):
        try:
            self.client.connect((address, port))
        except socket.error, e:
            print >> sys.stderr, e
            self.client.close()
            sys.exit()

    def disconnect(self):
        self.client.close()
