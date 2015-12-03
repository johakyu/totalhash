from __future__ import print_function

import ConfigParser
import hmac
import hashlib
import urllib2
import sys
import argparse
from os import path, environ

configuration_path = path.join(environ['HOME'], '.totalhash.rc')


def make_request(query_url):

    try:
        request = urllib2.Request(query_url, 'TC TotalHash Client')
        h_url = urllib2.urlopen(request)
    except urllib2.HTTPError, e:
        if e.code == 404:
            print('[*] Error: Failed to find data')
        return None
    return h_url.read()


def query(user, api_key, query, is_analysis):

    query_signature = hmac.new(key=api_key, msg=query, digestmod=hashlib.sha256)
    url_query_sig = query_signature.hexdigest()

    if is_analysis:
        analysis_url = 'https://api.totalhash.cymru.com/analysis/' + query + '&id=' + user + '&sign=' + url_query_sig
    else:
        analysis_url = 'https://api.totalhash.cymru.com/search/' + query + '&id=' + user + '&sign=' + url_query_sig

    analysis_response = make_request(analysis_url)

    return analysis_response


def handle_cfg():
    cfg_obj = ConfigParser.ConfigParser()
    cfg_obj.read(configuration_path)

    config = {}

    for section_name in cfg_obj.sections():
        if section_name == 'Credentials':
            config['Username'] = cfg_obj.get('Credentials', 'User')
            config['API Key'] = cfg_obj.get('Credentials', 'API Key')

    return config


def check_cfg():
    if path.isfile(configuration_path):
        return True
    else:
        return False


def argument_init():
    argument_parser_obj = argparse.ArgumentParser(description='Basic Python API client for TotalHash')
    argument_parser_obj.add_argument('--hash',
                                     help='MD5 or SHA1 checksum')
    argument_parser_obj.add_argument('--ip',
                                     help='IP address connection or DNSRR')
    argument_parser_obj.add_argument('--dnsrr',
                                     help='DNS record requested')

    return argument_parser_obj.parse_args()


def main():

    query_type = False

    ap = argument_init()

    if check_cfg():
        configuration = handle_cfg()

        if ap.hash:
            query_data = ap.hash
            query_type = True
        elif ap.ip:
            query_data = 'ip:%s' % ap.ip
        elif ap.dnsrr:
            query_data = 'dnsrr:%s' % ap.dnsrr
        else:
            print('[*] Specify data to query',
                  end='\n',
                  file=sys.stderr)
            return

        response = query(configuration['Username'], configuration['API Key'],
                         query_data, query_type)

        if response:
            print(response)

    else:
        print('[*] Error: Could not locate configuration file.',
              end='\n',
              file=sys.stderr)

if __name__ == '__main__':
    main()
    sys.exit(0)
