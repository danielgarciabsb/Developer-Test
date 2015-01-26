#!/usr/bin/python
# coding: utf-8

# imports
import sock

# classes

client = sock.SockClient()
client.connect("191.237.249.140",64006)
encryptedMessagedata = client.getEncryptedMessage()
decodedmessage = client.getDecodedMessage(encryptedMessagedata)
client.sendDecodedMessage(decodedmessage)
client.getServerResponse()
client.disconnect()