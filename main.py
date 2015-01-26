#!/usr/bin/python
# coding: utf-8

# imports
import sock

# classes

client = sock.SockClient()
client.connect("191.237.249.140",64006)
# Get message data and decrypt it
encryptedMessagedata = client.getEncryptedMessage()
decodedmessage = client.getDecodedMessage(encryptedMessagedata)
# Send the decoded message data to the client
client.sendDecodedMessage(decodedmessage)
# Get the server response
serverresponse = client.getServerResponse()
decodedresponse = client.getDecodedMessage(serverresponse)
client.disconnect()
if(decodedresponse == 'OK'):
    print "The server sent the 'OK' message. All done successfully!"