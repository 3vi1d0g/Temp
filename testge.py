import socket

HOST='66.42.55.226'
PORT=8888
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))
msg1="111|test|test|test"
s.send(msg1)
print msg1
date=s.recv(1024)
print date
s.send(msg1)