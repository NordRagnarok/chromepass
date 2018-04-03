#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import sqlite3
import csv
import json
import argparse
from contextlib import contextmanager

try:
    import win32crypt
except:
    pass

OUTPUT_FILENAME = 'chromepass-passwords'


class OutputFile(object):

    def __init__(self, _type):
        self.type = _type

    def open(self):
        return self.type.open_file()

    def write(self, file, content):
        self.type.write_into_file(file, content)


class CSV(object):
    FILENAME = '{}.csv'.format(OUTPUT_FILENAME)

    @contextmanager
    def open_file(self):
        fp = open(CSV.FILENAME, 'wb')
        yield fp
        fp.close()
        print("Data written to {}".format(CSV.FILENAME))

    def write_into_file(self, _file, content):
        _file.write('origin_url,username,password \n'.encode('utf-8'))
        for data in content:
            _file.write(('%s, %s, %s \n' % (data['origin_url'], data['username'], data['password'])).encode('utf-8'))


class JSON(object):
    FILENAME = '{}.json'.format(OUTPUT_FILENAME)

    @contextmanager
    def open_file(self):
        fp = open(JSON.FILENAME, 'w')
        yield fp
        fp.close()
        print("Data written to {}".format(JSON.FILENAME))

    def write_into_file(self, _file, content):
        json.dump({'password_items': content}, _file)


def args_parser():

    output_mapping = {
        'csv': CSV(),
        'json': JSON()
    }

    parser = argparse.ArgumentParser(description="Retrieve Google Chrome Passwords")
    parser.add_argument("-o", "--output", choices=['csv', 'json'], help="Output passwords to [ CSV | JSON ] format.")
    parser.add_argument("-d", "--dump", help="Dump passwords to stdout. ", action="store_true")

    args = parser.parse_args()
    if args.dump:
        for data in main():
            print(data)
    else:
        info = main()
        try:
            output(info, output_mapping[args.output])
            return

        except Exception as e:
            print(repr(e))
            parser.print_help()

def main():
    info_list = []
    path = getpath()
    try:
        connection = sqlite3.connect(path + "Login Data")
        with connection:
            cursor = connection.cursor()
            v = cursor.execute(
                'SELECT action_url, username_value, password_value FROM logins')
            value = v.fetchall()

        if (os.name == "posix") and (sys.platform == "darwin"):
            print("Mac OSX not supported.")
            sys.exit(0)

        for information in value:
            if os.name == 'nt':
                password = win32crypt.CryptUnprotectData(
                    information[2], None, None, None, 0)[1]
                if password:
                    info_list.append({
                        'origin_url': information[0],
                        'username': information[1],
                        'password': str(password)
                    })

            elif os.name == 'posix':
                info_list.append({
                    'origin_url': information[0],
                    'username': information[1],
                    'password': information[2]
                })

    except sqlite3.OperationalError as e:
        e = str(e)
        if e == 'database is locked':
            print('[!] Make sure Google Chrome is not running in the background')
            sys.exit(0)
        elif e == 'no such table: logins':
            print('[!] Something wrong with the database name')
            sys.exit(0)
        elif e == 'unable to open database file':
            print('[!] Something wrong with the database path')
            sys.exit(0)
        else:
            print(e)
            sys.exit(0)

    return info_list


def getpath():
    try:
        # This is the Windows Path - assuming user running Windows
        path_name = os.getenv('localappdata') + os.path.join('Google', 'Chrome', 'User Data', 'Default')
    except OSError as e:
        print(repr(e))
        path_name = ''

    if (os.name == "posix") and (sys.platform == "darwin"):
        # This is the OS X Path
        path_name = os.getenv('HOME') + "/Library/Application Support/Google/Chrome/Default/"
    if os.name == "posix":
        # This is the Linux Path
        path_name = os.getenv('HOME') + '/.config/google-chrome/Default/'

    if not os.path.isdir(path_name):
        print("[!] Chrome Doesn't exists")
        sys.exit(0)

    return path_name


def output(info, output_type):
    output_class = OutputFile(output_type)
    try:
        with output_class.open() as fp:
            output_class.write(fp, info)
    except EnvironmentError:
        print('EnvironmentError: cannot write data')


if __name__ == '__main__':
    args_parser()

