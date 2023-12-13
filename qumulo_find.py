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
import shutil
import hashlib
import pprint
pp = pprint.PrettyPrinter(indent=4)
import os
from random import randrange
import urllib3
urllib3.disable_warnings()

class AtomicCounter:

    def __init__(self, initial=0):
        """Initialize a new atomic counter to given initial value (default 0)."""
        self.value = initial
        self._lock = threading.Lock()


    def increment(self, num=1):
        """Atomically increment the counter by num (default 1) and return the
        new value.
        """
        with self._lock:
            self.value += num
            return self.value

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
def job_swap():
    global bl_flag
    global backlog
    while True:
        time.sleep(10)
        if job_queue.qsize() < JQ_FLOOR and os.path.exists(swap_file):
            done = False
            read_max = False
            i = 1
            new_size = 0
            while not done:
                print("SWAPPING....")
                with f_lock:
                    print("SWAP HAS LOCK")
                    swph = open(swap_file, "r")
                    for l in swph:
                        l = l.replace("'", '"')
                        if not read_max:
                            jqe = json.loads(l)
                            job_queue.put(jqe)
                            i += 1
                        else:
                            if not os.path.exists(swap_file + '.new'):
                                nswph = open(swap_file + '.new', 'w')
                            nswph.write(l)
                            new_size += 1
                        if i >= (int((JQ_CEILING - JQ_FLOOR)/2)) or (i >= 50000):
                            read_max = True
                    done = True
                    swph.close()
                    print("SWAP DONE READING: " + str(i))
                    if read_max:
                        nswph.close()
                        shutil.copyfile(swap_file + '.new', swap_file)
                        os.remove(swap_file + '.new')
                        backlog = AtomicCounter(new_size)
                        print("NEW SWAP FILE: " + str(backlog.value))
                    else:
                        print("NO MORE SWAPPING")
                        os.remove(swap_file)
                        backlog = AtomicCounter()
                        bl_flag = False
            print("SWAP_DONE!")

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
    if res.status_code == 200:
        results = json.loads(res.content.decode('utf-8'))
#        pp.pprint("RES [" + api + " ] : " + str(results))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def check_mtime(file, t_crit, t_limit):
#    print(file)
 #   print(criteria)
    t_limit = t_limit*86400
    if '.' in file['modification_time']:
        ftf = file['modification_time'].split('.')
        f_time = ftf[0]
    else:
        f_time = file['modification_time'][:-1]
    try:
        f_ts = datetime.timestamp(datetime.strptime(f_time, '%Y-%m-%dT%H:%M:%S'))
    except ValueError:
        sys.stderr.write("BAD TIME TIME FOR " + file['path'] + " : " + file['modification_time'])
        return(False)
    if t_crit.endswith('gt'):
#        print("MFTS: " + str(f_ts) + ' // ' + str(now - t_limit))
        if f_ts < now - t_limit:
            return(True)
    elif t_crit.endswith('lt'):
        if f_ts > now - t_limit:
            return(True)
    elif t_crit.endswith('eq'):
        if f_ts == now - t_limit:
            return(True)
    return(False)

def check_atime(file, t_crit, t_limit):
    t_limit = t_limit*86400
    if '.' in file['access_time']:
        ftf = file['access_time'].split('.')
        f_time = ftf[0]
    else:
        f_time = file['access_time'][:-1]
    try:
        f_ts = datetime.timestamp(datetime.strptime(f_time, '%Y-%m-%dT%H:%M:%S'))
    except ValueError:
        sys.stderr.write("BAD TIME TIME FOR " + file['path'] + " : " + file['access_time'])
        return(False)
    if t_crit.endswith('gt'):
        if f_ts < now - t_limit:
            return(True)
    elif t_crit.endswith('lt'):
        if f_ts > now - t_limit:
            return(True)
    elif t_crit.endswith('eq'):
        if f_ts == now - t_limit:
            return(True)
    return(False)

def check_size(file, t_crit, t_limit):
    f_size = int(file['size'])
    if t_crit.endswith('gt'):
        if f_size > t_limit:
            return(True)
    elif t_crit.endswith('lt'):
        if f_size < t_limit:
            return(True)
    elif t_crit.endswith('eq'):
        if f_size == t_limit:
            return(True)
    return(False)
def check_extension (file, ext_list):
    fn_f = file['name'].split('.')
    f_ext = fn_f[-1]
    for ext in ext_list:
        if f_ext == ext:
            return (True)
    return(False)
def check_path(file, path_list):
    for pat in path_list:
        if pat in file['path']:
            return (True)
    return(False)

def check_name(file, name_list):
    for name_pattern in name_list:
        if name_pattern in file['name']:
            return(True)
    return(False)

def add_job_to_queue(job_data):
    global bl_flag
    if (bl_flag) or (JQ_CEILING > 0 and job_queue.qsize() >= JQ_CEILING):
        bl_flag = True
        with f_lock:
            swp = open(swap_file, "a")
            swp.write(str(job_data) + "\n")
            swp.close()
            backlog.increment()
    else:
        job_queue.put(job_data)
    return

def walk_tree(addr_list, job, criteria):
#    print("WCRIT= " + str(criteria))
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
        if top_info == "404":
            print('GOT 404 in j_id')
        dprint(str(top_info))
        top_id = top_info['id']
    else:
        top_id = job['id']
    running_threads.append(th_name)
    print("Scanning " + path + " on node " + addr_list[job_ptr]['name'] + " [JQ: " + str(job_queue.qsize()) + "] [RJ: " + str(len(running_threads)) + "]  [BL: " + str(backlog.value) + " : " + str(bl_flag) + "]")
    done = False
    next = ''
    while not done:
        if not next:
            top_dir = qumulo_get(addr_list[job_ptr]['address'], '/v1/files/' + top_id + '/entries/?limit=500')
            if top_dir == "404":
                print('GOT 404 in next loop: ' + top_id)
                break
        else:
#            print("THREAD " + th_name + " PAGING: " + next)
            top_dir = qumulo_get(addr_list[job_ptr]['address'], next)
            if top_dir == "404":
                print("GOT 404 in else loop: " + + top_id)
        for dirent in top_dir['files']:
            if dirent['type'] == "FS_FILE_TYPE_DIRECTORY":
                dprint("ADDING " + dirent['path'] + " to JQ")
                add_job_to_queue({'id': dirent['id'], 'path': dirent['path']})
#                job_queue.put({'id': dirent['id'], 'path': dirent['path']})
            elif dirent['type'] == "FS_FILE_TYPE_FILE":
#                print("FOUND_FILE: " + dirent['path'])
                crit_ok = True
                if criteria:
                    for c in criteria:
                        if c.startswith('mtime'):
                            if not check_mtime(dirent, c, criteria[c]):
                                crit_ok = False
                                break
                        if c.startswith('atime'):
                            if not check_atime(dirent, c, criteria[c]):
                                crit_ok = False
                                break
                        if c == "extension":
                            if not check_extension(dirent, criteria[c]):
                                crit_ok = False
                                break
                        if c == 'path':
                            if not check_path(dirent, criteria[c]):
                                crit_ok = False
                                continue
                        if c == 'name':
                            if not check_name(dirent, criteria[c]):
                                crit_ok = False
                                continue
                        if c.startswith("size"):
                            if not check_size(dirent, c, criteria[c]):
                                crit_ok = False
                                continue
                if crit_ok:
                    if not fh[th_name]:
                        if len(path) < 100:
                            fp_f = path.split('/')
                            fpath = '_'.join(fp_f)
                            fpath = fpath.replace(':', '_')
                            fh[th_name] = open('.' + fpath + '.part', "w")
                        else:
                            fpath = "._" + hashlib.md5(path.encode()).hexdigest() + ".part"
                            fh[th_name] = open(fpath,"w")
                            oprint("# " + path, fh[th_name])
                    mtime_f = dirent['modification_time'].split('.')
                    atime_f = dirent['access_time'].split('.')
                    oprint(dirent['path'] + "," + mtime_f[0] + "," + atime_f[0] + "," + dirent['size'], fh[th_name])
                    write_flag = True
            else:
                continue
        try:
            next = top_dir['paging']['next']
            if not next:
                done = True
        except:
            done = True
    if write_flag:
        fh[th_name].close()
        parts_queue.put('.' + fpath + '.part')
    running_threads.remove(th_name)

def log_clean():
    files = os.listdir('.')
    for f in files:
        if (f.startswith('._') and f.endswith('.part')) or (f.startswith('.') and f.endswith('.swap')):
            os.remove(f)

def get_search_criteria(crit_file):
    crit = {}
    cf = open(crit_file)
    cf_s = cf.read()
    cf.close()
    crit_cand = json.loads(cf_s)
    valid_critera = ['mtime', 'atime', 'size', 'path', 'name', 'extension']
    for ck in crit_cand:
        if not ck[:1].isalpha():
            continue
        if ck == 'mtime':
            if crit_cand[ck][0] == '<':
                crit['mtime_lt'] = int(crit_cand[ck][1:])
            elif crit_cand[ck][0] == '>':
                crit['mtime_gt'] = int(crit_cand[ck][1:])
            else:
                crit_cand['mtime_eq'] = int(crit_cand[ck][1:])
        elif ck == 'atime':
            if crit_cand[ck][0] == '<':
                crit['atime_lt'] = int(crit_cand[ck][1:])
            elif crit_cand[ck][0] == '>':
                crit['atime_gt'] = int(crit_cand[ck][1:])
            else:
                crit_cand['atime_eq'] = int(crit_cand[ck][1:])
        elif ck == 'size':
            if crit_cand[ck][0] == '>':
                crit['size_gt'] = int(crit_cand[ck][1:])
            elif crit_cand[0] == '<':
                crit['size_lt'] = int(crit_cand[ck][1:])
            else:
                crit_cand['atime_eq'] = int(crit_cand[ck][1:])
        elif ck in valid_critera:
            crit[ck] = crit_cand[ck]
        else:
            sys.stderr.write("Unknown Criteria Found: " + ck + " ... ignoring.\n")
    dprint(str(crit))
    return(crit)


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
    fname = "qfind.csv"
    crit_file = "criteria.json"
    criteria = {}
    JQ_CEILING = 1000000
    JQ_FLOOR = 400000
    f_lock = threading.Lock()
    swap_file = ".job_queue.swap"
    backlog = AtomicCounter()
    bl_flag = False

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:m:T:o:s:w:', ['--help', '--DEBUG', '--token=', '--creds=', '--mtime=',
                                                            '--threads=', '--output=', '--search_file=', '--watermarks='])
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
        if opt in ('-o', '--output'):
            fname = a + ".csv"
        if opt in ('s', '--search_file'):
            crit_file = a
        if opt in ('-w', '--watermarks'):
            marks = a.split(':')
            JQ_CEILING = int(marks[0])
            JQ_FLOOR = int(marks[1])

    (qumulo, path) = args[0].split(':')
    criteria = get_search_criteria(crit_file)
    log_clean()
    now = int(datetime.timestamp(datetime.now()))
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
# Start Swap Thread
    if JQ_CEILING > 0:
        threading.Thread(name='swap', target=job_swap, daemon=True).start()
# Start Tree Walk Threads
    job = {'path': path, 'id': ''}
    threading.Thread(name='walk_tree', target=walk_tree, args=(addr_list, job, criteria)).start()
    print("Waiting for Jobs to Queue")
    time.sleep(20)
    while not job_queue.empty() or len(running_threads) > 0 or bl_flag:
        if not job_queue.empty() and len(running_threads) < max_threads:
#            if JQ_CEILING and job_queue.qsize() > JQ_CEILING:
#                while len(running_threads) > int(max_threads/2):
#                    print("CEILING: JQ: " + str(job_queue.qsize()) + " // RQ: " + str(len(running_threads)))
#                    time.sleep(5)
            job = job_queue.get()
            dprint("START: " + str(job))
            threading.Thread(name=job['path'], target=walk_tree, args=(addr_list, job, criteria)).start()
        elif not job_queue.empty():
            time.sleep(10)
            print("\nQueue: " + str(job_queue.qsize()))
            print("Running Threads: " + str(len(running_threads)))
        else:
            if len(running_threads) > 1:
                print("Waiting for " + str(len(running_threads)) + " threads to complete")
                print("BL: " + str(bl_flag))
            else:
                print ("Waiting for 1 thread to complete: " + str(running_threads))
            time.sleep(10)
        dprint("THREADS [" + str(len(running_threads)) + "]:")
#        if DEBUG:
#           for t in threading.enumerate():
#                dprint(t.name)

    if not parts_queue.empty():
        print("Generating Report...")
        ofh = open(fname, "w")
        ofh.write("Path,Mtime,Atime,Size\n")
        while not parts_queue.empty():
            p = parts_queue.get()
            rfh = open(p, "r")
            for l in rfh:
                if not l.startswith('#'):
                    oprint(l.rstrip(), ofh)
            rfh.close()
            os.remove(p)
        ofh.close()
    print("Done!")







