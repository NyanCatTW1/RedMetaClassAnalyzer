#!/usr/bin/python3
import traceback
import sys
import socketserver
from datetime import datetime
import time
import os
import shutil


# https://stackoverflow.com/a/57008707
# Context manager that copies stdout and any exceptions to a log file
class Tee(object):
    def __init__(self, filename):
        self.file = open(filename, 'w')
        self.stdout = sys.stdout

    def __enter__(self):
        sys.stdout = self

    def __exit__(self, exc_type, exc_value, tb):
        sys.stdout = self.stdout
        if exc_type is not None:
            self.file.write(traceback.format_exc())
        self.file.close()

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
        self.flush()

    def flush(self):
        self.file.flush()
        self.stdout.flush()


dirName = "./WRedLogs/"
logName = dirName + "WRedLog.txt"
if os.path.isfile(logName):
    bakName = logName + "-" + str(int(time.time())) + ".txt"
    shutil.copy2(logName, bakName)

sys.stdout = Tee(logName)


class MyTCPClientHandler(socketserver.StreamRequestHandler):
    timeout = 1800
    def handle(self):
        print()
        print("Connection established on", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "from", self.client_address)

        outEnd = 10 # ord("\n")
        while True:
            data = self.rfile.read1()
            if not data:
                break
            print(data.decode(errors="ignore"), end="")
            outEnd = data[-1]

        if outEnd != 10:
            # Print missing newline
            print()
        print("Disconnected")


# https://pythontic.com/socketserver/threadingtcpserver/introduction
socketserver.ForkingTCPServer.allow_reuse_address = True
TCPServerInstance = socketserver.ForkingTCPServer(("0.0.0.0", 420), MyTCPClientHandler)
print("WRedLogger started")
TCPServerInstance.serve_forever()
