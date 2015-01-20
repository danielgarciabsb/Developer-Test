#!/usr/bin/python
# coding: utf-8

# imports
import sock

# classes

client = sock.SockClient()
client.connect("191.237.249.140",64006)
print sum([ ord(x) for x in client.getPacketLength() ])
print client.getMD5Sum().encode('hex')