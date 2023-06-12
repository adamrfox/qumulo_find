#!/usr/bin/python
from __future__ import print_function
import sys
import getopt
import getpass
import requests
import threading
from queue import Queue
import time
from datetime import datetime
import urllib.parse
import json
from random import randrange
import urllib3
urllib3.disable_warnings()

def usage():
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        print(message + "\n")

def oprint(message, fh):
    if not fh:
        print(message)
    else:
        fh.write(message + "\n")

def python_input (message):
    if int(sys.version[0]) > 2:
        value = input(message)
    else:
        value = raw_input(message)
    return(value)

def api_login(qumulo, user, password, token):
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = python_input("User: ")
        if not password:
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    return(auth_headers)

def auth_refresh(qumulo, user, password, token, refresh):
    global auth
    while True:
        time.sleep(refresh*60)
        new_header = api_login(qumulo, user, password, token)
        dprint("API_LOGIN_UPDATE")
        auth = new_header

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    res= requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
    if res.status_code == 200:
        results = json.loads(res.content.decode('utf-8'))
        try:
            results['paging']['next']
        except:
            return(results)
        if not results['paging']['next'] :
            return(results)
        print("PAGE!")
        exit(4)
    else:
        sys.stderr.write("API ERROR:\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)


def walk_tree(addr_list, path, time_flag, time_limit):
    write_flag = False
    th = threading.current_thread()
    th_name = th.name
    fh[th_name] = ""
    job_ptr = randrange(len(addr_list))
    top_info = qumulo_get(addr_list[job_ptr]['address'], '/v1/files/' + urllib.parse.quote(path, safe='') + '/info/attributes')
    print(top_info)
    top_id = top_info['id']
    top_dir = qumulo_get(addr_list[job_ptr]['address'], '/v1/files/' + top_id + '/entries/')
    for dirent in top_dir['files']:
        if dirent['type'] == "FS_FILE_TYPE_DIRECTORY":
            job_queue.put(dirent['id'])
        elif dirent['type'] == "FS_FILE_TYPE_FILE":
            if len(dirent[time_flag]) > 20:
                f_time = dirent[time_flag][:-11]
            else:
                f_time = dirent[time_flag][:-1]
            try:
                f_ts = datetime.timestamp(datetime.strptime(f_time, '%Y-%m-%dT%H:%M:%S'))
            except ValueError:
                sys.stderr.write("BAD TIME TIME FOR " + dirent['path'] + " : " + dirent[time_flag])
                continue
            if f_ts < time_limit:
                if not fh[th_name]:
                    fp_f = path.split('/')
                    fpath = '_'.join(fp_f)
                    fpath = fpath.replace(':', '_')
                    fh[th_name] = open('.' + fpath + '.part', "w")
                oprint(dirent['path'] + "," + f_time + "," + dirent['size'], fh[th_name])
                write_flag = True
    if write_flag:
        fh[th_name].close()
    exit(0)


if __name__ == "__main__":
    DEBUG = False
    token = ""
    user = ""
    password = ""
    headers = {}
    timeout = 360
    mtime = 0
    time_flag = ""
    addr_list = []
    max_threads = 0
    fh = {}
    job_queue = Queue()
    THREADS_FACTOR = 10
    REAUTH_TIME = 10

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:m:T:', ['--help', '--DEBUG', '--token=', '--creds=', '--mtime=',
                                                            '--threads='])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ['-D', '--DEBUG']:
            DEBUG = True
        if opt in ['-t', '--token']:
            token = a
        if opt in ['-c', '--creds']:
            (user, password) = a.split(':')
        if opt in ['-m' , '--mtime']:
            time_limit = int(a)*86400
            time_flag = "modification_time"
        if opt in ('-T', '--threads'):
            max_threads = int(a)
    (qumulo, path) = args[0].split(':')
    if time_flag:
        now = int(datetime.timestamp(datetime.now()))
        find_time = now-time_limit
    auth = api_login(qumulo, user, password, token)
    dprint(str(auth))
    net_data = requests.get('https://' + qumulo + '/v2/network/interfaces/1/status/', headers=auth,
                            verify=False, timeout=timeout)
    dprint(str(net_data.content))
    net_info = json.loads(net_data.content.decode('utf-8'))
    for node in net_info:
        if node['interface_details']['cable_status'] == "CONNECTED" and node['interface_details'][
            'interface_status'] == "UP":
            for ints in node['network_statuses']:
                addr_list.append({'name': node['node_name'], 'address': ints['address']})
    if max_threads == 0:
        max_threads = THREADS_FACTOR * len(addr_list)
    dprint(str(addr_list))
    print("Using up to " + str(max_threads) + " threads across " + str(len(addr_list)) + " nodes.")
# Start Auth Thread
    threading.Thread(name='auth', target=auth_refresh, args=(qumulo, user, password, token,REAUTH_TIME),daemon=True).start()
# Start Tree Walk Threads
    if time_flag:
        threading.Thread(name='walk_tree', target=walk_tree, args=(addr_list, path, time_flag, find_time)).start()