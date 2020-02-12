# Python 
import os
import sys
import argparse
import requests
import time
import json

def getAppBOM(_apiurl, _auth, _orgid, _appid, _appname, _bomfile):
    _headers = {'Accept':'application/json'}
    _resturi = 'WS2/domains/{}/applications/{}/thirdparty'.format(_orgid, _appid)
    
    try:
        print('Making a call to get BOM for {} app: {}/{}'.format(_appname, _apiurl, _resturi))
        _jsonResult = requests.get(_apiurl+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=10).json()
        print('Call succeeded!')
        
        # Loop through all libraries
        for item in _jsonResult['thirdParties']:
            # Header: 'app_id,app_name,lib_name,lib_ver,lib_lastver,lib_lang,cve_count'
            
            # Check if JSON element is present, otherwise specify that data is unavailable
            _libVer = item['version'] if ('version' in item) else 'n/a'
            _libLastVer = item['lastVersion'] if ('lastVersion' in item) else 'n/a'
            _libLang = item['languages'] if ('languages' in item) else 'n/a'
            _libcve = len(item['cve']['vulnerabilities']) if ('cve' in item) else 0

            _bomfile.write('{},"{}","{}","{}","{}","{}",{}\n'.format(_appid, _appname, item['name'], _libVer, _libLastVer, _libLang, _libcve))

    except Exception as e:
        print('Error: {}'.format(str(e)))
        #print(json.dumps(_jsonResult).replace("\'", "*"))
        #exit (0)
    
    return (1)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Retrieves bill of material (BOM) information for all application in organization portfolio")
    parser.add_argument('-c', '--connection', action='store', dest='connection', required=True, help='Specifies URL to the Highlight service')
    parser.add_argument('-u', '--username', action='store', dest='username', required=True, help='Username to connect to RestAPI')
    parser.add_argument('-p', '--password', action='store', dest='password', required=True, help='Password to connect to RestAPI')
    parser.add_argument('-o', '--orgid', action='store', dest='orgid', required=True, help='ID of the organization/company in Highlight')
    parser.add_argument('-f', '--filepath', action='store', dest='filepath', required=True, help='Path and name of CSV file where script results will be stored')
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    _args = parser.parse_args()
    _auth = (_args.username, _args.password)

    try:
        # Create file where results of query will be stored
        _bomfile = open(_args.filepath, "w") # Create file
        _bomfile.write('app_id,app_name,lib_name,lib_ver,lib_lastver,lib_lang,cve_count\n') # Write file header
    
        # Get list of all applications
        _headers = {'Accept':'application/json'}
        _resturi = 'WS2/domains/{}/applications?expand='.format(_args.orgid)
    
        print('Making a call to get list of apps: {}/{}'.format(_args.connection, _resturi))
        _jsonResult = requests.get(_args.connection+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=10).json()
        print('Call succeeded!')
        
        # Loop through each application to get and store the BOM
        for item in _jsonResult:
            print('Getting BOM for application "{}" (id:{})'.format(item['name'], item['id']))
            getAppBOM(_args.connection, _auth, _args.orgid, item['id'], item['name'], _bomfile)
         
         # Close file
        _bomfile.close()
        print ('Bill of Material information stored in file: {}'.format(_args.filepath))
        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)
    