# Python 
import os
import sys
import argparse
import requests
import time
import json

def getAppBOM(_apiurl, _auth, _orgid, _appid, _bomfile):
    _headers = {'Accept':'application/json'}
    _resturi = 'WS2/domains/{}/applications/{}/thirdparty'.format(_orgid, _appid)
    
    try:
        print('Making a call to Highlight RestAPI: {}/{}'.format(_apiurl, _resturi))
        _jsonResult = requests.get(_apiurl+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=10).json()
        print('Call succeeded!')
        
        # Loop through all libraries
        for item in _jsonResult['thirdParties']:
            # Header: 'app_id,app_name,lib_name,lib_ver,lib_lastver,lib_lang,cve_count'
            if ('cve' in item):
                _bomfile.write('{},"{}","{}","{}","{}","{}",{}\n'.format(_appid, "appname", item['name'], item['version'], item['lastVersion'], item['languages'], len(item['cve']['vulnerabilities'])))
            else:
                _bomfile.write('{},"{}","{}","{}","{}","{}",{}\n'.format(_appid, "appname", item['name'], item['version'], item['lastVersion'], item['languages'], 0))
    except Exception as e:
        print('Error: {}'.format(str(e)))
        print('JSON: {}'.format(_jsonResult))
    
    return (1)

if __name__ == "__main__":
    """ Access RESTAPI, then check results """
    parser = argparse.ArgumentParser(description="""\n\nCAST Blocking Rule Check - \n Reads RestAPI, Pulls scores, runs a test and returns 0 if all is ok, and 10 if not""")
    
    parser.add_argument('-c', '--connection', action='store', dest='connection', required=True, help='Specifies URL to the Highlight service')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True, help='Username to connect to RestAPI')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True, help='Password to connect to RestAPI')
    parser.add_argument('-o', '--orgid', action='store', dest='orgid', required=True, help='ID of the organization/company in Highlight')
    parser.add_argument('-a', '--appid', action='store', dest='appid', required=True, help='ID of target application in Highlight')		
    #parser.add_argument('-r', '--report', action='store', dest='report', required=False, default="summary",
    #   choices=['summary', 'etc.'], help='Pre-defined report name')
    
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    _results = parser.parse_args()
    _auth = (_results.username, _results.password)

    _bomfile = open("c:/temp/app_libs.csv", "w") # Create file
    _bomfile.write('app_id,app_name,lib_name,lib_ver,lib_lastver,lib_lang,cve_count\n') # Write file header

    getAppBOM(_results.connection, _auth, _results.orgid, _results.appid, _bomfile)
    #print('Results: ' + str(_jsonResults))
    
    _bomfile.close() # Close file
    
    #f = open('index.html','w')
    #f.write('<html><head></head><body></body>')
    #f.write(json2html.convert(json = _jsonResults))
    #f.write('</html>')
    #f.close()
    sys.exit(0)

