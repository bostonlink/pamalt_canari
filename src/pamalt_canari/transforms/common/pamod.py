#!/usr/bin/env python
# Copyright (C) 2012 pamalt Developer.
# This file is part of pamalt - https://github.com/bostonlink/pamalt
# See the file 'LICENSE' for copying permission.

# PaloAlto Networks API Python Module
# Author: David Bressler

import urllib2, urllib
import time
import xml.etree.ElementTree as ET
from os import getcwd, path

from canari.config import config
from canari.utils.fs import cookie, fsemaphore
from canari import easygui

def http_get(full_url):
    try:
        req = urllib2.Request(full_url)
        ret = urllib2.urlopen(req)
        return ret.read()
    except urllib2.HTTPError as e:
        return e

# Checks config keys and overwrites config file after initial authentication to the PA API

def get_login():
    fn = cookie('pakey')
    if not path.exists(fn):
        f = fsemaphore(fn, 'wb')
        f.lockex()
        msg = "Please Enter the following Palo Alto Configuration"
        fv = easygui.multpasswordbox(msg, "PaloAlto Credentials", ['Username:', 'Password:'])
        pau, pap = fv
        base_url = 'https://%s/api/?' % config['pamalt/pa_hostname']
        params_dic = {'type': 'keygen', 'user': pau, 'password': pap}

        enc_params = urllib.urlencode(params_dic)
        full_url = base_url + enc_params
        ret_data = http_get(full_url)
        root = ET.fromstring(ret_data)
        key = root[0][0].text
        f.write(key)
    else:
        f = fsemaphore(fn)
        f.locksh()
        key = f.read()
    return key

# PA Dynamic report function, must provide a valid dynamic report name
# See pa_dyn_rname.txt list for all valid report names

def pa_dyn_report(reportname, key, period=''):
    
    base_url = 'https://%s/api/?' % config['pamalt/pa_hostname']
    params_dic = {'type': 'report', 'reporttype': 'dynamic', 'reportname': reportname, 'period': period, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)

# PA predefined report function, must provide a valid predefined report name

def pa_pred_report(reportname, key):

    base_url = 'https://%s/api/?' % config['pamalt/pa_hostname']
    params_dic = {'type': 'report', 'reporttype': 'predefined', 'reportname': reportname, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)

# PA log query function to query pa logs and return the results in XML format

def pa_log_query(log_type, key, query=''):

    base_url = 'https://%s/api/?' % config['pamalt/pa_hostname']
    params_dic = {'type': 'log', 'logtype': log_type, 'query': query, 'key': key}
    
    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    ret_data = http_get(full_url)
    root = ET.fromstring(ret_data)
    return root[0][1].text
    
def pa_log_get(jobid, key):

    base_url = 'https://%s/api/?' % config['pamalt/pa_hostname']
    params_dic = {'type': 'log', 'action': 'get', 'job-id': jobid, 'key': key}

    enc_params = urllib.urlencode(params_dic)
    full_url = base_url + enc_params
    return http_get(full_url)