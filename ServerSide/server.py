#! /usr/bin/env python
#i -*- coding:utf-8 -*-
import re
import socket
import threading
import time
from verify import *
from time import ctime
from sqlalchemy import create_engine
from sqlalchemy import Column, String, Integer, Unicode, PickleType, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

random_num = []
exitFlag = 0
pcrFlag = False
eventFlag = False
status = False

# Create the Engine sqlite://<nohostname>/<path>
DB_CONNECT = 'sqlite:///Secure.db'
engine = create_engine(DB_CONNECT, echo=True, encoding='utf-8', convert_unicode=True)
DB_Session = sessionmaker(bind=engine)
session = DB_Session()
Base = declarative_base()
Base.metadata.create_all(engine)

def init_db():
    Base.metadata.create_all(engine)
 
def drop_db():
    Base.metadata.drop_all(engine)

class PcrRecord(Base):
    __tablename__ = 'PcrRecord'
    id = Column(Integer, primary_key=True)
    time = Column(String(64))    
    pcr0 = Column(String(20))    
    pcr1 = Column(String(20))    
    pcr2 = Column(String(20))    
    pcr3 = Column(String(20))    
    pcr4 = Column(String(20))    
    pcr5 = Column(String(20))    
    pcr6 = Column(String(20))    
    pcr7 = Column(String(20))    
    event = relationship("EventRecord", order_by="EventRecord.id", backref="pcr")
    secretKey = Column(String(20))    

class EventRecord(Base):
    __tablename__ = 'EventRecord'
    id = Column(Integer, primary_key=True)
    number = Column(Integer, ForeignKey("PcrRecord.id"))
    eventType = Column(String(20))
    eventDetails = Column(String(128))
    eventSize = Column(String(8))

class start_server(threading.Thread):
    def __init__(self, name, counter):
        threading.Thread.__init__(self)
        self.name = name
        self.counter = counter
    def run(self):
        ip_port = ('',8000)
        buffer_size = 2048
        web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #web.settimeout(CHECK_TIMEOUT)
        web.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        web.bind(ip_port)
        web.listen(5)
        print "Server Listening..."
        global exitFlag
        print exitFlag
        
        while exitFlag == 0:
          conn, addr = web.accept()
          print "Connection from: ", addr
          while exitFlag == 0:
            data = conn.recv(buffer_size)
            if not data:
              break
            print "Recv Data: ", data
            content = msg_process(data)
            print "Sent Data: ", content
            conn.sendall(content.encode("utf-8"))    

            # verify the client's credentials after data collection
            if eventFlag == True and pcrFlag == True:
                start_sqlite()
                status = verify_record()
                conn.sendall(status.encode("utf-8"))    
                eventFlag, pcrFlag = False, False  
                exitFlag = 1
          conn.close()
        web.close()

'''Example of Event Log:
     Event PCR Index: 5
     Event Type: Action
     SHA1 Digest: B6AE9742D3936A4291CFED8DF775BC4657E368C0
     Event Size: 47'''

def start_sqlite():
    if (pcrFlag == True) and (eventFlag == True):
        pcrItem, eventItem = [], []
        with open('pcr.log', 'r') as f:
            for line in f.readlines():
                pcrItem.append(line)
        with open('event.log', 'r') as f:
            for line in f.readlines():
                index, category, digest, size = event_process(line)
                eventItem.append([index, category, digest, size])
        update_db(pcrItem, eventItem)
    else:
        pass            


def event_process(line):
    index, category, digest, size = 0, 0, 0, 0
    if "Index" in line: index = re.search(r'(\d)', line).group(1)
    if "Type"  in line: index = re.search(r':(.*)', line).group(1)
    if "SHA1"  in line: index = re.search(r':(.*)', line).group(1)
    if "Size"  in line: index = re.search(r'(\d+)', line).group(1)
    return index, category, digest, size


def update_db(pcr, event):
    eventList = []
    for item in event:
        e = EventRecord(
              number = item[0],
              eventType = item[1],
              eventDetails = item[2],
              eventSize = item[3])
        eventList.append(e)

    redudency = 8 - len(pcr)
    for index in range(redudency):
        pcr.append(0) 
    item = PcrRecord(
             pcr0 = pcr[0],     
             pcr1 = pcr[1],     
             pcr2 = pcr[2],     
             pcr3 = pcr[3],     
             pcr4 = pcr[4],     
             pcr5 = pcr[5],     
             pcr6 = pcr[6],     
             pcr7 = pcr[7],
             time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    item.event = eventList

    session.add(item)
    session.commit()

 
def msg_processing(data):
    if data.find("Hello") >= 0: 
        nounce = re.search(r'(\d+)').group(0)
        random_num.append()
        print "[INFO] Get a nounce from the client: ", nounce, "\n"
        return "Confirm: Auth Invitation"
    elif data.find("Event") >= 0: 
        filename = "event.log"
        dump_data(data, filename)
        eventFlag = True
        print "[INFO] Collect Event Logs\n"
        return "Event saved"
    elif data.find("TPM") >= 0:
        filename = "pcr.log"
        dump_data(data, filename)
        pcrFlag = True
        print "[INFO] Collect PCR Logs\n"
        return "PCR saved"
    else:
        print "[Warning] Meaningless", data, "\n"
        return "Nothing saved"
            
def dump_data(data, filename):
    with open(filename, 'w') as f:
        f.write(data)
        f.close()
    
threadLock = threading.Lock()
threads = []
server_thread = start_server('server_line', 5)
server_thread.start()

server_thread.join()
Msg = ("Safe" if (status == False) else "Warning")  
print "Verification Completed: Status ", Msg
