#!/usr/bin/python
from __future__ import print_function
import sys
import getopt
import getpass
import requests
import base64
import json
import urllib3
urllib3.disable_warnings()

def usage():
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        print(message + "\n")

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
            auth_headers = {'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    return(auth_headers)

if __name__ == "__main__":
    DEBUG = False
    token = ""
    user = ""
    password = ""
    headers = {}
    timeout = 360
    mtime = 0
    time_flag = ""

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:c:m:', ['--help', '--DEBUG', '--token=', '--creds=', '--mtime='])
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
            mtime = int(a)
            time_flag = "mtime"
    (qumulo, path) = args[0].split(':')
    auth = api_login(qumulo, user, password, token)
    print(auth)