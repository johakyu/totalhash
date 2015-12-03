#!/usr/bin/python

'''
Basic demonstration Python API client for TotalHash
Requires a Totalhash user ID and API key (https://totalhash.cymru.com/contact-us/)
Takes malware SHA1 on command line prompt and returns results in XML
'''

import hmac
import hashlib
import urllib2

user_id='User ID'
api_key='TotalHash API Key'
query_sha1 = raw_input('SHA1 to query:')
query_signature = hmac.new(key=api_key, msg=query_sha1, digestmod=hashlib.sha256)
url_query_sig = query_signature.hexdigest()

analysis_url = 'https://api.totalhash.cymru.com/analysis/' + query_sha1 + '&id=' + user_id + '&sign=' + url_query_sig

print urllib2.urlopen(analysis_url).read()
