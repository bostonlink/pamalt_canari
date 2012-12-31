#!/usr/bin/env python

import xml.etree.ElementTree as ET
from time import sleep

from canari.framework import configure
from canari.maltego.entities import IPv4Address
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
    label='To Threats [PaloAlto]',
    description='Returns PaloAlto threat entities associated with the IP address entity',
    uuids=[ 'pamalt_canari.v2.paMaltIPToThreat' ],
    inputs=[ ( 'PaloAlto', IPv4Address ) ],
    debug=True
)

def dotransform(request, response):

    # Check PAN Authentication AND KEY
    key = pamod.get_login()
    
    # Create and submit the query to the API and return the jobid
    ip_entity = request.value

    query = '(addr.dst in %s) or (addr.src in %s)' % (ip_entity, ip_entity)
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
    threat_list = []
    for d in log_list:
        if d['threatid'] not in threat_list:
            response += paThreat(
                d['threatid'],
                tid=d['tid'],
                ipsrc=d['src'],
                ipdst=d['dst']
            )
            threat_list.append(d['threatid'])

    return response