#!/usr/bin/env python

import xml.etree.ElementTree as ET
from time import sleep

from canari.maltego.entities import IPv4Address
from canari.framework import configure
from common.entities import paThreat
from common import pamod

__author__ = 'bostonlink'
__copyright__ = 'Copyright 2012, Pamalt_canari Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'bostonlink'
__email__ = 'bostonlink@pentest-labs.org'
__status__ = 'Development'

__all__ = [
    'dotransform',
    'onterminate'
]

@configure(
    label='To IP Destination [PaloAlto]',
    description='Returns PaloAlto IP destination entities associated with the PaloAlto threat',
    uuids=[ 'pamalt_canari.v2.paMaltThreatToIPdst' ],
    inputs=[ ( 'PaloAlto', paThreat ) ],
    debug=False
)

def dotransform(request, response):

    # Check PAN Authentication AND KEY
    key = pamod.get_login()
    
    # Create and submit the query to the API and return the jobid
    tid = request.fields['tid']

    query = '(threatid eq %s)' % (tid)
    jobid = pamod.pa_log_query('threat', key, query)
    sleep(5)

    # Loop function to check if the log query job is done
    root = ET.fromstring(pamod.pa_log_get(jobid, key))
    for status in root.findall(".//job/status"):
        while status.text == 'ACT':
            sleep(5)
            root = ET.fromstring(pamod.pa_log_get(jobid, key))
            for status in root.findall(".//job/status"):
                if status.text == 'FIN':
                    break

    # parse the log data and create dictionaries stored in a list for each individual log
    log_list = []
    for entry in root.findall(".//log/logs/entry"):
        entry_dic = {}
        for data in entry:
            entry_dic[data.tag] = data.text

        log_list.append(entry_dic)

    # Create the Maltego Entity
    ip_list = []
    for d in log_list:
        if d['dst'] not in ip_list:
            response += IPv4Address(
                d['dst'],
                tid=d['tid'],
                ipsrc=d['src'],
            )
            ip_list.append(d['dst'])
    
    return response