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
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def oprint(message, fh):
    if not fh:
        print(message)
    else:
        fh.write(message + "\n")

def total_keys(test_dict):
    return (0 if not isinstance(test_dict, dict)
    else len(test_dict) + sum(total_keys(val) for val in test_dict.values()))

def api_login(qumulo, user, password, token):
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input("User: ")
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
        dprint("RES [" + api + " ] : " + str(results))
        return(results)
    else:
        sys.stderr.write("API ERROR:\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)


def walk_tree(addr_list, job, time_flag, time_limit):
    write_flag = False
    th = threading.current_thread()
    th_name = th.name
    fh[th_name] = ""
    path = job['path']
    j_id = job['id']
    dprint("J_ID: " + j_id)
    dprint("PATH = " + path)
    job_ptr = randrange(len(addr_list))
    if not j_id:
        top_info = qumulo_get(addr_list[job_ptr]['address'], '/v1/files/' + urllib.parse.quote(path, safe='') + '/info/attributes')
        dprint(str(top_info))
        top_id = top_info['id']
    else:
        top_id = job['id']
    running_threads.append(th_name)
    print("Scanning " + path + " on node " + addr_list[job_ptr]['name'])
    done = False
    next = ''
    while not done:
        if not next:
            top_dir = qumulo_get(addr_list[job_ptr]['address'], '/v1/files/' + top_id + '/entries/')

        else:
#            print("THREAD " + th_name + " PAGING: " + next)
            top_dir = qumulo_get(addr_list[job_ptr]['address'], next)
        for dirent in top_dir['files']:
            if dirent['type'] == "FS_FILE_TYPE_DIRECTORY":
                print("ADDING " + dirent['path'] + " to JQ")
                job_queue.put({'id': dirent['id'], 'path': dirent['path']})
            elif dirent['type'] == "FS_FILE_TYPE_FILE":
#                print("FOUND_FILE: " + dirent['path'])
                if '.' in dirent[time_flag]:
                    ftf = dirent[time_flag].split('.')
                    f_time = ftf[0]
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
        try:
            next = top_dir['paging']['next']
            if not next:
                done = True
        except:
            print("THREAD_END: " + th_name)
            done = True
    if write_flag:
        fh[th_name].close()
        parts_queue.put('.' + fpath + '.part')
    print("T_DONE: " + th_name)
    running_threads.remove(th_name)


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
    parts_queue = Queue()
    running_threads = []
    THREADS_FACTOR = 10
    REAUTH_TIME = 10

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:m:T:', ['--help', '--DEBUG', '--token=', '--creds=', '--mtime=',
                                                            '--threads='])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ['-D', '--DEBUG']:
            DEBUG = True
            dfh = open('debug.out', 'w')
            dfh.close()
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
        job = {'path': path, 'id': ''}
        threading.Thread(name='walk_tree', target=walk_tree, args=(addr_list, job, time_flag, find_time)).start()
    print("Waiting for Jobs to Queue")
    time.sleep(20)
    print("JQ1: " + str(job_queue.queue))
    print("RUNQ1: " + str(running_threads))
    while not job_queue.empty() or len(running_threads) > 0:
        if not job_queue.empty() and len(running_threads) < max_threads:
            job = job_queue.get()
            print("START: " + str(job))
            threading.Thread(name=job['path'], target=walk_tree, args=(addr_list, job, time_flag, find_time)).start()
        elif not job_queue.empty():
            time.sleep(10)
            print("\nQueue: " + str(job_queue.qsize()))
            print("Running Threads: " + str(len(running_threads)))
        else:
            print("Waiting for " + str(len(running_threads)) + " to complete")
            time.sleep(10)
        print("JQ: " + str(job_queue.queue))
        print("RUNQ: " + str(running_threads))
        print("THREADS:")
        for t in threading.enumerate():
            print(t.name)

    print("JQF: " + str(job_queue.queue))
    print("RUNQF: " + str(running_threads))





