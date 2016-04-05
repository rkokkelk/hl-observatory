import os
import rsa
import sys
import json
import math
import time
import atexit
import base64
import random
import signal
import hashlib
import argparse
import datetime
import queue
import pprint

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

import logging
import logging.handlers

from analyse import analyse

import threading
from threading import Thread

pid = '/tmp/analytics.pid'
pp = pprint.PrettyPrinter(indent=4)
log = logging.getLogger("Analytics")

# Configurations
pd.set_option('display.mpl_style', 'default')
pd.set_option('display.width', 300)
pd.set_option('display.max_columns', 10)

def setup_logging(debug):
    formatter = logging.Formatter("[%(asctime)s] (%(levelname)s) %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    if debug:
        log.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    log.addHandler(ch)
try:
    syslog = logging.handlers.SysLogHandler(address='/dev/log')
    syslog.setLevel(logging.WARN)
    syslog.setFormatter(formatter)
    log.addHandler(syslog)

except:
	pass

def setup_arguments():
    parser = argparse.ArgumentParser(description='Hacking Labs Observatory')
    parser.add_argument('-d', action='store_true', dest='debug',default=False, help='Enable debug logging')
    parser.add_argument('-t', action='store', type=str, required=True, dest='data_dir',default=False,help='Directory containing the JSON formats')
    parser.add_argument('-p', action='store', type=str, required=False, default='analytics',dest='result',help='Directory to which the results of the analytics are written')
    return parser.parse_args()

def get_data():
    data = dict()
    data_files = [f for f in os.listdir(args.data_dir) 
            if os.path.isfile(os.path.join(args.data_dir, f)) and f.endswith('.json')]

    for data_file in data_files:
        # Very hacky, I know
        sep1 = data_file.find('_')
        sep2 = data_file.find('_',sep1+1)
        sep3 = data_file.rfind('_')
        sep4 = data_file.find('.json')
        ip = data_file[0:sep1]
        country = data_file[sep1+1:sep2]
        timestamp = data_file[sep3+1:sep4]

        if 'No' in country:
            country = country[-2:]

        log.debug("(%s) [%s] %s %s", country, ip, timestamp, data_file)

        if country not in data:
            data[country] = dict()

        with open(os.path.join(args.data_dir, data_file), 'r') as f:
            json_data = json.load(f)

        data[country][timestamp] = json_data
    return data

def create_data_frame(country, timestamp, data):
    df = pd.DataFrame()

    # Lambda's for extracting data from json
    domain = lambda cur_domain: cur_domain
    dns = lambda cur_domain: data[cur_domain]['dns'] if 'dns' in data[cur_domain] else []
    finger_print = lambda cur_domain: data[cur_domain]['ssl']['sha256'] if 'ssl' in data[cur_domain] and 'sha256' in data[cur_domain]['ssl'] else float('NaN')
    ssl_cipher_mode = lambda cur_domain: data[cur_domain]['ssl']['ciphers'][2] if 'ssl' in data[cur_domain] and 'ciphers' in data[cur_domain]['ssl'] else float('NaN')
    ssl_key_size = lambda cur_domain: data[cur_domain]['ssl']['ciphers'][0] if 'ssl' in data[cur_domain] and 'ciphers' in data[cur_domain]['ssl'] else float('NaN')
    ssl_match_name = lambda cur_domain: data[cur_domain]['ssl']['match_hostname'] if 'ssl' in data[cur_domain] and 'match_hostname' in data[cur_domain]['ssl'] else float('NaN')
    ssl_issuer = lambda cur_domain: data[cur_domain]['ssl']['issuer'] if 'ssl' in data[cur_domain] and 'issuer' in data[cur_domain]['ssl'] else float('NaN')
    ssl_common_name = lambda cur_domain: data[cur_domain]['ssl']['common_name'] if 'ssl' in data[cur_domain] and 'common_name' in data[cur_domain]['ssl'] else float('NaN')
    ssl_alt_names = lambda cur_domain: data[cur_domain]['ssl']['subjectAltName'] if 'ssl' in data[cur_domain] and 'subjectAltName' in data[cur_domain]['ssl'] else float('NaN')

    df['country'] = list(map(lambda cur_domain: country, data))
    df['timestamp'] = list(map(lambda cur_domain: timestamp, data))
    df['domain'] = list(map(domain, data))
    df['dns'] = list(map(dns, data))
    df['sha256'] = list(map(finger_print, data))
    df['key_size'] = list(map(ssl_cipher_mode, data))
    df['cipher_mode'] = list(map(ssl_key_size, data))
    df['validSSL'] = list(map(ssl_match_name, data))
    df['commonName'] = list(map(ssl_common_name, data))
    df['issuer'] = list(map(ssl_issuer, data))
    df['altNames'] = list(map(ssl_alt_names, data))

    return df

def generate_cipher_mode_graphs(df):
    prev_country = ''
    keysize = df[['country','cipher_mode']].groupby(['country','cipher_mode']).size()
    for (country, cipher_mode) in keysize.index:
        if prev_country == country:
            continue
        else:
            prev_country = country
        name = '{0}_cipher_mode.png'.format(country)
        plot = keysize[country].plot(kind='bar')
        save_figure(plot, name)

    log.info('Generated cipher-mode graphs')

def save_figure(plot, name):
    fig = plot.get_figure()
    fig.savefig(os.path.join(args.result, name))
    log.debug('Save figure (%s)', name)

def main():

    log.info("Hacking Labs Analytics started")

    data = get_data()
    df = pd.DataFrame()

    for country in data:
        for timestamp in data[country]:
            df_tmp = create_data_frame(country, timestamp, data[country][timestamp])
            df = df.append(df_tmp, ignore_index=True)

    log.info('Finished importing, [%d] rows to DataFrame', df.shape[0])

    generate_cipher_mode_graphs(df)
    get_smallest_keysize(df)

    log.info("Analytics ended")

if __name__ == "__main__":

    global args
    args = setup_arguments()
    setup_logging(args.debug)

    main()
