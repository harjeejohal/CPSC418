#!/usr/bin/env python3

import socket

HOSTNAME = '127.0.0.1'
PORT = 65432


def get_user_input():
    user = input('Enter Username: ')
    pw = input('Enter Password: ')

    return user, pw


def setup_server_connection(user, pword):
    init_connection = True
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, PORT))
        s.sendall(b'Hello World')
        data = s.recv(1024)
        print('Received', repr(data))
        data = s.recv(1024)
        print('Received', repr(data))


username, password = get_user_input()
setup_server_connection(username, password)
