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
status = "Safe"

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
        buffer_size = 20480
        web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #web.settimeout(CHECK_TIMEOUT)
        web.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        web.bind(ip_port)
        web.listen(5)
        print "[INFO] Server Listening..."
        global exitFlag, eventFlag, pcrFlag, random_num, status
        
        while exitFlag == 0:
          session_key = 0
          conn, addr = web.accept()
          print "[INFO] Connection from: ", addr
          while exitFlag == 0:
            data = conn.recv(buffer_size)
            if not data:
              break

            print "[INFO] Recv Data: ", data, "\n"
            content, encode = msg_processing(data, session_key)
            print "[INFO] Sent Original Data: ", content
            print "[INFO] Sent Encoded  Data: ", encode

            # create session key if handshake established
            if len(random_num) == 3 and session_key == 0:
                session_key = get_session_key(random_num)
                print "[INFO] The Random number List: ", random_num
                random_num = []

            if encode != "None":
              conn.sendall(encode.encode("utf-8"))    
            else:
              pass

            # verify the client's credentials after data collection
            if eventFlag == True and pcrFlag == True:
                print '[INFO] Completed Data Collection\n'
                start_sqlite(b2a_hex(session_key))
                status = verify_record()
                aes_encrypt = AES_ENCRYPT(session_key)  
                result = aes_encrypt.encrypt(status)
                
                conn.sendall(result.encode("utf-8"))    
                eventFlag, pcrFlag = False, False  
                session_key, exitFlag = 0, 1
          conn.close()
        web.close()

class start_tftp(threading.Thread):
    def __init__(self, name, reset):
        threading.Thread.__init__(self)
        self.name = name
        self.reset = reset
    def run(self):
        ip_port = ('',69)
        buffer_size = 512
        web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #web.settimeout(CHECK_TIMEOUT)

'''Example of Event Log:
     Event PCR Index: 5
     Event Type: Action
     SHA1 Digest: B6AE9742D3936A4291CFED8DF775BC4657E368C0
     Event Size: 47'''

def verify_record():
    # Assume Safe in Default
    result = "Safe" 
    return result 

# start pasring and save the uploaded TFTP data
def start_sqlite(session_key):
    import os
    os.system("tr -d '\\000' < /tftpboot/PcrValue.log > PcrValue.log")
    os.system("tr -d '\\000' < /tftpboot/Event.log > Event.log")
    pcrItem, eventItem = [], []
    with open('PcrValue.log', 'r') as f:
        for line in f.readlines():
            pcrItem.append(line)

    i, index, category, digest, size = 0, 0, 0, 0, 0 
    with open('Event.log', 'r') as f:
        for line in f.readlines():
            tag, value = event_process(line)
            if tag == 1: index    = value; i += 1
            if tag == 2: category = value; i += 1
            if tag == 3: digest   = value; i += 1
            if tag == 4: size     = value; i += 1
            if i % 4 == 0:
                i = 0
                eventItem.append([index, category, digest, size])
            else: pass
    print pcrItem, '\n\n', eventItem
    update_db(pcrItem, eventItem, session_key)


def event_process(line):
    line = line.encode('utf-8')
    tag, value = 3, line
    if "Index" in line: tag, value = 1, re.search(r'(\d)', line).group(1)
    if "Type"  in line: tag, value = 2, re.search(r':(.*)', line).group(1)
    if "SHA1"  in line: tag, value = 3, re.search(r':(.*)', line).group(1)
    if "Size"  in line: tag, value = 4, re.search(r'(\d+)', line).group(1)
    return tag, value


def update_db(pcr, event, session_key):
    eventList = []
    for item in event:
        e = EventRecord(
              number = item[0],
              eventType = item[1],
              eventDetails = item[2],
              eventSize = item[3])
        eventList.append(e)

    # redudency = 8 - len(pcr)
    # for index in range(redudency):
    #     pcr.append(0) 

    item = PcrRecord(
             pcr0 = pcr[0],     
             pcr1 = pcr[1],     
             pcr2 = pcr[2],     
             pcr3 = pcr[3],     
             pcr4 = pcr[4],     
             pcr5 = pcr[5],     
             pcr6 = pcr[6],     
             pcr7 = pcr[7],
             secretKey = session_key, 
             time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    item.event = eventList

    session.add(item)
    session.commit()

 
def msg_processing(data, session_key):
    global random_num, eventFlag, pcrFlag

    # plain text transmission berfore handshake established 
    if data.isspace() == False and session_key == 0:
        if data.find("Hello") >= 0: 
            nounce = re.search(r'(-*\d+)', data).group(0)
            random_num.append(int(nounce))
            server_nounce = random_number()
            random_num.append(server_nounce)
            print "[INFO] Get a Nounce from the client: ", nounce, "\n"
            value = "Confirm Auth Invitation : " + str(server_nounce) 
            return value, value  
        elif data.find("Master") >= 0: 
            premaster_key = re.search(r'(-*\d+)', data).group(0)
            random_num.append(int(premaster_key))
            print "[INFO] Get Pre-Master Key from the client: ", premaster_key, "\n"
            return "Done", "Done"
        else:
            return "None", "None"

    # data encryption with session key after handshake
    elif data.isspace() == False and session_key != 0:
        print "[INFO] Data to be decryted: ", data, "\n"
        print "[Debug] The session Key(Hex): ", b2a_hex(session_key)
        try: 
          aes_encrypt = AES_ENCRYPT(session_key)  
          clean = clean_data(data)
          decode = aes_encrypt.decrypt(clean)
          print "[INFO] Cleaned data: ", clean
          print "[INFO] Decrypted Data: ", decode
        except:
          decode = "None"

        if decode.find("Event") >= 0: 
            eventFlag = True
            print "[INFO] Collect Event Logs\n"
            encode = aes_encrypt.encrypt("Event Saved")
            return "Event saved", encode

        elif decode.find("PCR") >= 0:
            pcrFlag = True
            print "[INFO] Collect PCR Logs\n"
            encode = aes_encrypt.encrypt("PCR Saved")
            return "PCR saved", encode
        else:
            return "None", "None"
    
    # received nothing
    else:
        print "[Warning] Meaningless", data, "\n"
        return "None", "None"
    
        
def clean_data(data):
    clean = re.search(r'=*(\w+)', data).group(1)
    if len(clean) % 2 == 0: pass
    else: clean = clean[:-1]
    return clean

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

# drop_db()
# init_db()
# start_sqlite('cdbusi')
