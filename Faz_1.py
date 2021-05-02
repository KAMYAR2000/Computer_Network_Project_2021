import threading
from queue import Queue
import socket
from datetime import datetime
import argparse
import time
import encodings.idna

def mythread():
    time.sleep(1000)

def num_threads():
    threads = 0     #thread counter
    y = 1000000     #a MILLION of 'em!
    for i in range(y):
        try:
            x = threading.Thread(target=mythread, daemon=True)
            threads += 1    #thread counter
            x.start()       #start each thread
        except RuntimeError:    #too many throws RuntimeError
            break
    return threads


print_lock = threading.Lock()

def portscan_All(port):
    socket.setdefaulttimeout(timeout)
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      result = sock.connect_ex((remoteServerIP, port))
      with print_lock:
          if result == 0:
            print("Port {}: 	 Open".format(port))
      sock.close()
    except:
        pass

def portscan_Query(port):
    socket.setdefaulttimeout(timeout)
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      result = sock.connect_ex((remoteServerIP, port))
      with print_lock:
          if result == 0:
            print("Port {}: 	 Open".format(port))
          else:
            print("Port {}: 	 closed".format(port))
      sock.close()
    except:
        pass

def threader_All():
    while True:
        worker = q.get()
        portscan_All(worker)
        q.task_done()

def threader_query():
    while True:
        worker = q.get()
        portscan_Query(worker)
        q.task_done()

q = Queue()

def sniffing(index = 0, selectedService = '', beginNum = 0, endNum = 0):
    t1 = datetime.now()
    if index == 0:
        for worker in range(1, 65535):
            q.put(worker)
    if index == 1:
        for worker in range(1, 1023):
            q.put(worker)

    if index == 3:
        for worker in range(beginNum, endNum+1):
            q.put(worker)

    if index is not 2:
        for x in range(numberThreads):
            t = threading.Thread(target=threader_All)
            t.daemon = True
            t.start()

    if index==2:
        if selectedService == "HTTP":
            q.put(80)
        if selectedService == "TLS":
            q.put(465)
        if selectedService == "SMTP":
            q.put(25)
            q.put(465)
            q.put(587)
        if selectedService == "FTP":
            q.put(21)
        if selectedService == "TELNET":
            q.put(23)
        if selectedService == "SSH":
            q.put(22)

        for x in range(numberThreads):
            t = threading.Thread(target=threader_query)
            t.daemon = True
            t.start()

    q.join()
    t2 = datetime.now()
    total =  t2 - t1
    print ('Scanning Completed in: ', total)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help="Host")
    parser.add_argument('--numThreads', help="Number of threads", type=int)
    parser.add_argument('--timeOut', help="timeout of each port", type=float)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-a', '--All', action='store_true', help="return all available ports")
    group.add_argument('-r', '--Reserved', action='store_true', help="return reserved available ports")
    group.add_argument('-q', '--Query', action='store_true', help="Application layer services")
    group.add_argument('-p', '--Patch', action='store_true', help="patch of ports")

    parser.add_argument('-s','--Service', help="selected Service for query")

    parser.add_argument('--BeginNum', help="Beginning of selected patch", type=int)
    parser.add_argument('--EndNum', help="End of selected patch", type=int)

    args = parser.parse_args()

    numberThreads = 8
    if args.numThreads:
        if 500 < args.numThreads:
            print("Too many threads!!!")
            exit()
        numberThreads = args.numThreads

    timeout = 0.3
    if args.timeOut:
        timeout = args.timeOut

    remoteServerIP = socket.gethostbyname(args.host)
    print("-" * 60)
    print("Please wait, scanning remote host", remoteServerIP)
    print("-" * 60)

    if args.All:
        sniffing()
    elif args.Reserved:
        sniffing(1)
    elif args.Query:
        if args.Service == None:
            print("please enter Service....")
            exit()
        sniffing(2, selectedService=args.Service)
    elif args.BeginNum:
        if args.EndNum == None:
            print("please enter endNum....")
            exit()
        sniffing(3, beginNum= args.BeginNum, endNum=args.EndNum)
