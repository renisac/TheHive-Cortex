#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from cifsdk.client.http import HTTP as Client
from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
from datetime import datetime
import json

class CIFv3(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.remote = self.get_param('config.remote', None, 'Missing CIF remote')
        self.token = self.get_param('config.token', None, 'Missing CIF token')
        self.d_confidence = self.get_param('config.confidence')
        self.verify_ssl = self.get_param('config.verify_ssl')
        self.group_list = self.get_param('config.group')
        self.custom_tlp_map = self.get_param('config.tlp_map')

        self.TLP_MAP = {
            "0": 'WHITE',
            "1": 'GREEN',
            "2": 'AMBER',
            "3": 'RED'
        }

        # load in custom tlp map
        if self.custom_tlp_map and self.custom_tlp_map != '':
            try:
                self.TLP_MAP.update(json.loads(self.custom_tlp_map))
            except Exception as e:
                self.error("Error loading tlp map: {}".format(e))


    def run(self):
        Responder.run(self)
        confidence = None

        indicators = []

        # case details
        if self.get_param('data._type') == 'case_artifact':
            a = {}
            a['indicator'] = self.get_param('data.data', None, 'Missing indicator')
            a['tags'] = self.get_param('data.tags')
            a['tlp'] = self.get_param('data.tlp', None)
            a['desc'] = self.get_param('data.message', None)
            a['lasttime'] = self.get_param('data.createdAt', None)
            if self.get_param('data.updatedAt'):
                    a['lasttime'] = self.get_param('data.updatedAt')
            indicators.append(a)

        # alert details
        if self.get_param('data._type') == 'alert':
            for i in self.get_param('data.artifacts'):
                a = {}
                a['indicator'] = i['data']
                a['tags'] = i['tags']
                a['tlp'] = self.get_param('data.tlp', None)
                a['desc'] = self.get_param('data.description', None)
                a['lasttime'] = self.get_param('data.createdAt', None)
                if self.get_param('data.updatedAt'):
                    a['lasttime'] = self.get_param('data.updatedAt')
                indicators.append(a)
        
        # instantiate CIF client
        try:
            cli = Client(token=self.token, remote=self.remote, verify_ssl=self.verify_ssl)
        except Exception as e:
            self.error('Unable to establish CIF client: {}'.format(e))

        # setup tracking vars
        success_submitted = 0
        expected_submitted = len(indicators) * len(self.group_list)
        error_list = []
        
        for i in indicators:

            # map TLP to word
            tlp = self.TLP_MAP[str(i['tlp'])]

            # process tags
            tags = i['tags']
            for t in list(tags):
                # confidence tag check
                if 'confidence:' in t:
                    tags.remove(t)
                    (k, v) = t.split(':')
                    confidence = int(v)
                # remove other directive tags
                elif ':' in t:
                    tags.remove(t)

            # set to default confidence if not defined
            if not confidence:
                confidence = self.d_confidence

            # convert lasttime
            lasttime = datetime.utcfromtimestamp(i['lasttime']/1000).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # build indicator
            ii = {
                'indicator': i['indicator'],
                'confidence': confidence,
                'description': i['desc'],
                'tags': tags,
                'tlp': tlp,
                'lasttime': lasttime
            }

            # handle multiple submissions, one per group
            for group in self.group_list:
                ii['group'] = group

                # create indicator object
                try:
                    ii_obj = Indicator(**ii)
                except InvalidIndicator as e:
                    self.error("Invalid CIF indicator {}".format(e))
                except Exception as e:
                    self.error("CIF indicator error: {}".format(e))

                # submit indicator
                try:
                    _ = cli.indicators_create(ii_obj)
                    success_submitted += 1
                except Exception as e:
                    error_list.append("CIF submission error for indicator {}: {}".format(ii_obj, e))

        if error_list:
            self.error('{} indicator(s) submitted to CIF out of {}. Errors: {}'.format(success_submitted, 
                expected_submitted, error_list
                ))
        else:
            self.report({'message': '{} indicator(s) submitted to CIF out of {}'.format(success_submitted, expected_submitted)})

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='cifv3:submitted')]


if __name__ == '__main__':
    CIFv3().run()
