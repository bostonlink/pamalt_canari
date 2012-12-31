#!/usr/bin/env python

from canari.maltego.message import Entity, EntityField

__author__ = 'bostonlink'
__copyright__ = 'Copyright 2012, Pamalt_canari Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'bostonlink'
__email__ = 'bostonlink@pentest-labs.org'
__status__ = 'Development'

__all__ = [
    'PamaltEntity',
    'paThreat',
    'topAttackers',
    'topAttacks',
    'topSpyware',
    'topVictims',
    'topViruses',
    'topVulns'
]

@EntityField(name='ipsrc', propname='ipsrc', displayname='IP Source')
@EntityField(name='ipdst', propname='ipdst', displayname='IP Destination')
@EntityField(name='tid', propname='tid', displayname='Threat ID')
class PamaltEntity(Entity):
    namespace = 'pamalt'
 
@EntityField(name='subtype', propname='subtype', displayname='Threat Subtype')
@EntityField(name='count', propname='count', displayname='Count')
class paThreat(PamaltEntity):
    pass

class topAttackers(PamaltEntity):
    pass

class topAttacks(PamaltEntity):
    pass

class topSpyware(PamaltEntity):
    pass

class topVictims(PamaltEntity):
    pass

class topViruses(PamaltEntity):
    pass

class topVulns(PamaltEntity):
    pass