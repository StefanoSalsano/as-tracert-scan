#!/usr/bin/python

import subprocess
import pyasn
import argparse
import json
import ipaddress
import time
from datetime import datetime
import sys
import socket

# set to True when running in jupyter (avoids command line arguments)
RUN_IN_JUPYTER = False

# uncomment 'win' for windows, 'lin' for MAC and Linux
#OSTYPE = 'win'
OSTYPE = 'lin'

SCANNER_ID = 'my name and my computer'

# if true, a trace route is performed towards the AS listed in ASN_LIST_FILENAME
ASN_SCAN = False

# destination node for traceroute, it can be also changed with option -d
DEST = 'www.uniroma2.it'
DEST = 'www.baidu.com'

WRITE_TO_FILE = True
WRITE_FILENAME = 'asn_scan_output.txt'

READFROMFILE = False
FILENAME = 'output.txt'

ASN_LIST_FILENAME = 'asn_list.out'
ASN_NAMES_FILENAME = 'name_map.out'

if not WRITE_TO_FILE:
    global_out_file = sys.stdout
    global_separator = '\n'
else:
    global_out_file = open(WRITE_FILENAME, 'a')
    global_separator = '\t'



def run_traceroute(tracedest):
    if OSTYPE == 'lin':
        result = subprocess.run(['traceroute', '-n', tracedest], stdout=subprocess.PIPE)
    if OSTYPE == 'win':
        result = subprocess.run(['tracert', '-d', tracedest], stdout=subprocess.PIPE)
    trace = result.stdout.decode('utf-8')
    trace = trace.splitlines()
    return trace


def parse (trace):
    """trace is iterable (you can iterate over the lines)"""
    if OSTYPE == 'win':
        return windows_parse (trace)
    if OSTYPE == 'lin':
        return linux_parse (trace)


def windows_parse (trace):
    router_list = []
    for line in trace:
      #print (line)
      tokens = line.split() 
      if tokens:

        #print (tokens[0])
        try:
            num = int(tokens[0])
        except:
            num = 0

        #print(num)
        if num > 0:
            if tokens[len(tokens)-1] != 'out.' and tokens[len(tokens)-1] != 'scaduta.' and tokens[len(tokens)-1] != 'raggiungibile.':
                if tokens[1]!='*':
                    delay = tokens[1]
                elif tokens[2]!='*':
                    delay = tokens[2]
                else:
                    delay = tokens[3]
                if delay == '<1':
                    delay = '0'
                delay=int(delay)
                router_list.append([tokens[len(tokens)-1],num,delay])
          
    return router_list


def linux_parse(trace):
    router_list = []
    for line in trace:
        #print (line)
        tokens = line.split()
        if tokens:
            #print (tokens)
            #print (tokens[0], tokens[1])
            try:
                num = int(tokens[0])

            except:
                num = 0

            if num > 0:
                router_addr = ""
                if tokens[1]!='*':
                    #print (tokens[1])
                    router_addr = tokens[1]
                    delay = tokens[2]
                elif tokens[2]!='*':
                    router_addr = tokens[2]
                    delay = tokens[3]
                elif tokens[3]!='*':
                    router_addr = tokens[3]
                    delay = tokens[4]
                if router_addr != "":
                    router_list.append([router_addr,num,float(delay)])

    return router_list

def get_asn_info (router_list):
    """return a new_router_list with only public routers and an asn_list

        each record of the new_router_list is
        [ip_address, hop_number, delay, asn]

        each record of the asn_list is
        [asn, first_hop, last_hop, hop_number, min_delay]
        first_hop : the hop_number of the first router belonging to this AS in the path
        last_hop : the hop_number of the last router belonging to this AS in the path
        hop_number : the number of routers belonging to this AS in the path
        min_delay : the minumum RTT delay among all routers belonging to this AS in the path
        max_delay : the maximum RTT delay among all routers belonging to this AS in the path
    """
    new_router_list = []
    asn_list = []
    asn = -1
    asn_record = [0,0,0]
    first_public_router=-1
    for router in router_list:
        (a, b) = asndb.lookup(router[0])
        if a:
            if first_public_router == -1:
                #print ('router',router)
                first_public_router = router[1]-1
            router[1]=router[1]-first_public_router
            #print (router[0], a, b)
            router.append(a)
            new_router_list.append(router)
            if a != asn:
                asn = a
                #asn_list.append(a)
                asn_list.append([a,router[1],router[1],1,router[2],router[2]])
            else:
                asn_list[-1][2]=router[1]
                asn_list[-1][3]=asn_list[-1][3]+1
                if router[2] < asn_list[-1][4]:
                    asn_list[-1][4] = router[2]
                if router[2] > asn_list[-1][5]:
                    asn_list[-1][5] = router[2]
    asn_names_list = asn_num_to_name (asn_list)
    #print (new_router_list)
    #print (asn_list)
    return [new_router_list, asn_list, asn_names_list]

def build_asn_name_map():
    with open(ASN_NAMES_FILENAME, 'r') as myfile:
        data=myfile.read()    
        # parse file
        obj = json.loads(data)
    map = {}
    for record in obj:
        #print (record[0], record[1])
        map[record[0]]= record[1]
    return map

def asn_num_to_name(asn_list):
    output_list=[]
    for asn in asn_list:
        #print (asn[0])
        output_list.append(asn_name_map[asn[0]])
    return output_list

def is_ipv4_address(input_string):
    try:
        ipaddress.IPv4Address(input_string)
    except:
        return False
    return True

def my_out(my_line=''):
    global_out_file.write(str(my_line)+global_separator)

# implicit inputs: DEST, new_router_list, asn_list
def output_results():
    timestamp = time.time()
    dt_object = datetime.fromtimestamp(timestamp)
    #my_out()

    if READFROMFILE:
        my_out ('reading from file, unknown destination info')
    else:
        if is_ipv4_address(DEST):
            dest_ip=DEST
            my_out(DEST)
        else:
            dest_ip=socket.gethostbyname(DEST)
            my_out(DEST+' ('+dest_ip+')')
        #print (str(my_addr), separator, file = out_file)
        target_asn = asndb.lookup(dest_ip)[0]
        my_out(target_asn)
        my_out(asn_name_map[target_asn])
        if (target_asn and asn_list):
            if (target_asn == asn_list[-1][0]):
                my_out ('REACHED')
            else:
                my_out ('NOT_REACHED')
        else:
            my_out ('ERROR')                    

    #print ()
    my_out(SCANNER_ID)
    my_out (timestamp)
    my_out (dt_object)
    if new_router_list == []:
        sys.stderr.write('ERROR **********************************************************************************\n')
        sys.stderr.write(str(router_list)+'\n')
        sys.stderr.write('ERROR **********************************************************************************\n')
        sys.stderr.flush()
    my_out (new_router_list)
    my_out (asn_list)
    my_out (asn_num_to_name(asn_list)) 
    global_out_file.write('\n')
    global_out_file.flush()


if not RUN_IN_JUPYTER:
    #parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dest', dest='destination', default=DEST)
    parser.add_argument('-r', '--readfile', dest='read_from_file', action='store_true', default=READFROMFILE, help='read from file')
    parser.add_argument('-n', '--filename', dest='file_name', default=FILENAME)
    parser.add_argument('-a', '--asnscan', dest='asn_scan', action='store_true', default=ASN_SCAN)

    args = parser.parse_args()
    #print ('destination',args.destination)
    #print ('read from file',args.read_from_file)
    #print ('filename',args.file_name)
    DEST=args.destination
    READFROMFILE=args.read_from_file
    FILENAME=args.file_name
    ASN_SCAN=args.asn_scan

asndb = pyasn.pyasn('ipasn.dat')
#print (build_asn_name_map())
asn_name_map = build_asn_name_map()

if not ASN_SCAN:

    if READFROMFILE:
        #trace = open(FILENAME, "r")
        with open(FILENAME, 'r') as myfile:
            trace=myfile.read().splitlines()
            #print (trace)

    else:
        trace = run_traceroute(DEST)
        #print (trace)

    router_list = parse(trace)
    #print (router_list)

    [new_router_list, asn_list, asn_names_list] = get_asn_info (router_list)

    output_results()

else: #asn scan
    
    if READFROMFILE:
        print ('Reading from file is not compatible with ASN scan option')
        exit()

    with open(ASN_LIST_FILENAME, 'r') as myfile:
        data=myfile.read()

    # parse file
    obj = json.loads(data)

    for record in obj:
        my_net = ipaddress.ip_network(record[1])
        for my_addr in my_net.hosts():
            #print (my_addr)
            DEST=str(my_addr)
            trace = run_traceroute(DEST)
            #print (trace)

            router_list = parse(trace)
            #print (router_list)
            [new_router_list, asn_list, asn_names_list] = get_asn_info (router_list)
            output_results()
            print (DEST, asn_names_list)
            print ()
            break
        #break

