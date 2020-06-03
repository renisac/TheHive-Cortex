#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from datetime import datetime
import requests
import json
import math

class APWG(Responder):

    def __init__(self):
        Responder.__init__(self)
        
        if self.get_param('config.sandbox'):
            self.remote = 'https://api.sandbox.ecrimex.net'
        else:
            self.remote = 'https://api.ecrimex.net'
            
        self.token = self.get_param('config.token', None, 'Missing APWG API token')
        self.d_confidence = self.get_param('config.confidence')
        
        # iterate through all enabled endpoints
        self.enabled_endpoints = [k.replace('endpoint_', '', 1) for k,v in self.__dict__['_input']['config'].items() if k.startswith('endpoint_') and v is True]
        
        # maps hive dataTypes (key) to APWG API endpoint info (list(tuple)) where 0th tuple item is the endpoint url (/mal_ip or /phish) and 
        # 1st tuple item is the json attribute name expected for that apwg api endpoint during POST submission 
        # (e.g.: /phish expects the indicator passed with key 'url')
        # made the values a list in case apwg ever expands their api endpoints to accept multiple hive datatypes to various endpoints
        self.HIVE_TO_APWG_MAP = {
            'ip': [('mal_ip', 'ip')],
            'url': [('phish', 'url')]
        }
        
        # instantiate requests session for later api calls
        self.session = requests.Session()
        self.headers =  {   'Content-Type': 'application/json',
                            'Authorization': self.token,
                            'X-API-Token': self.token,
                            'User-Agent': 'APWG-Cortex-Responder-0.1'
                        }


    def run(self):
        Responder.run(self)
        
        # setup data prep vars
        confidence = None
        indicators = []
        
        # setup submission tracking vars
        success_submitted = 0
        tried_submitted = 0
        error_list = []
        
        # case details
        if self.get_param('data._type') == 'case_artifact':
        
            datatype = self.get_param('data.dataType')
            apwg_type = self.HIVE_TO_APWG_MAP.get(datatype, None)
            # if the datatype doesn't exist as a key in the map OR
            # if the first element in each tuple (endpoint name) in the list of tuples isn't contained in the enabled_endpoints, then no go
            if not apwg_type or not (set([t[0] for t in apwg_type]).intersection(self.enabled_endpoints)):
                self.error('Data type {} not supported or appropriate APWG API endpoint disabled in your APWG responder config for indicator {}'.format(
                    datatype, self.get_param('data.data')))
            
            a = {}
            a['indicator'] = self.get_param('data.data', None, 'Missing indicator')
            a['tags'] = self.get_param('data.tags')
            a['lasttime'] = self.get_param('data.createdAt', None)
            a['apwg_type'] = apwg_type
            indicators.append(a)

        # alert details
        if self.get_param('data._type') == 'alert':
        
            for i in self.get_param('data.artifacts'):
            
                datatype = i['dataType']
                apwg_type = self.HIVE_TO_APWG_MAP.get(datatype, None)
                # if the datatype doesn't exist as a key in the map OR
                # if the first element in each tuple (endpoint name) in the list of tuples isn't contained in the enabled_endpoints, then no go
                if not apwg_type or not (set([t[0] for t in apwg_type]).intersection(self.enabled_endpoints)):
                    error_list.append('Data type {} not supported or appropriate APWG API endpoint disabled in your APWG responder config for indicator {}'.format(
                        datatype, i['data']))
                    continue
                              
                a = {}
                a['indicator'] = i['data']
                a['tags'] = i['tags']
                a['lasttime'] = self.get_param('data.createdAt', None)
                if self.get_param('data.updatedAt'):
                    a['lasttime'] = self.get_param('data.updatedAt')
                a['apwg_type'] = apwg_type
                indicators.append(a)

        for i in indicators:

            # process tags
            tags = i['tags']
            for t in list(tags):
                if 'apwg:brand=' in t:
                    tags.remove(t)
                    i['brand'] = t.split('=', 1)[1]
                    
                if 'apwg:desc=' in t:
                    tags.remove(t)
                    i['desc'] = t.split('=', 1)[1]
                    
                # confidence tag check
                if 'apwg:confidence=' in t:
                    tags.remove(t)
                    v = t.split('=')[1]
                    if int(v) in [50, 90, 100]:
                        confidence = int(v)
                if 'confidence:' in t:
                    tags.remove(t)
                    v = t.split(':')[1]
                    if int(v) in [5, 9, 10]:
                        confidence = int(v) * 10
                    elif int(v) in [50, 90, 100]:
                        confidence = int(v)

            # set to default confidence if not defined
            if not confidence:
                confidence = self.d_confidence

            # hive provides createdAt with 13 digit epoch but apwg only accepts 10-digit epoch; convert and round down
            lasttime = math.floor(i['lasttime']/1000)

            # build indicator
            ii = {
                'confidence_level': confidence,
                'date_discovered': lasttime
            }
            
            if i.get('brand'):
                ii['brand'] = i['brand']
            else:
                ii['brand'] = 'generic'            

            # submit indicator to each apwg endpoint mapped to this indicator's hive data type
            for d in list(i['apwg_type']):
                api = self.remote + '/' + d[0]
                ifield = d[1]
                ii[ifield] = i['indicator']
                
                # description field only required/accepted by mal_ip endpoint
                if d[0] in ['mal_ip']:
                    if i.get('desc'):
                        ii['description'] = i['desc']
                    else:
                        ii['description'] = 'malicious ip'
                
                d = json.dumps(ii)
                
                tried_submitted += 1
                
                try:
                    r = self.session.post(api, data=d, headers=self.headers, timeout=5)
                except requests.exceptions.Timeout as err:
                    error_list.append('APWG submission timed out for indicator {}: {}'.format(ii, err))
                    
                if not 200 <= r.status_code <= 299:
                    if r.text != '':
                        msg = json.loads(r.text)
                        msg = '- ' + msg['error']['messages'][0]
                    else:
                        msg = ''
                    
                    if r.status_code == 403:
                        error_list.append('{} - Account permissions prevent data submission {} - Indicator: {}'.format(r.status_code, msg, ii))
                        
                    elif r.status_code == 404:
                        error_list.append('{} - Unauthorized API Token {} - Indicator: {}'.format(r.status_code, msg, ii))
                        
                    elif r.status_code == 412:
                        error_list.append('{} - Attempted to submit a whitelisted indicator {} - Indicator: {}'.format(r.status_code, msg, ii))
                        
                    else:
                        error_list.append('{} - Error submitting indicator to APWG {} - Indicator: {}'.format(r.status_code, msg, ii))
                else:
                    success_submitted += 1

        if error_list:
            self.error('{} indicator(s) submitted to APWG out of {}. Errors: {}'.format(success_submitted, tried_submitted, error_list))
            
        else:
            self.report({'message': '{} indicator(s) submitted to APWG'.format(success_submitted)})

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='apwg:submitted')]


if __name__ == '__main__':
    APWG().run()