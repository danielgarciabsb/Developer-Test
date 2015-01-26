#!/usr/bin/python
# coding: utf-8

# imports
import sock

# classes

client = sock.SockClient()
client.connect("191.237.249.140",64006)
client.getEncryptedMessage()
client.sendDecodedMessage()
client.getServerResponse()
client.disconnect()