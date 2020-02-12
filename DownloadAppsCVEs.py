# Python 
import os
import sys
import argparse
import requests
import time
import json

def getAppCVEs(_apiurl, _auth, _orgid, _appid, _appname, _bomfile):
    _headers = {'Accept':'application/json'}
    _resturi = 'WS2/domains/{}/applications/{}/thirdparty'.format(_orgid, _appid)
    
    try:
        try:
            print('Making a call to get BOM for {} app: {}/{}'.format(_appname, _apiurl, _resturi))
            _jsonResult = requests.get(_apiurl+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=30).json()
            print('1st RestAPI call to Highlight succeeded.')
        except requests.exceptions.RequestException as e:
            try:
                print('1st connection attempt to Highlight RestAPI failed. Trying again...')
                _jsonResult = requests.get(_apiurl+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=60).json()
                print('2nd call succeeded.')
            except requests.exceptions.RequestException as e:
                print('Failed to connect to Highlight API')
                print('Error: {}'.format(e))
                print('Aborting script...')
                sys.exit(0)
        
        # Loop through all libraries
        for _thirdParty in _jsonResult['thirdParties']:
            # Loop through CVEs reported in 3rd party components
            for _cve in _thirdParty['cve']['vulnerabilities']:
                # Check if JSON element is present, otherwise specify that data is unavailable
                _cveName = _cves['name'] if ('name' in _cve) else 'n/a'
                _cveDesc = _cves['description'] if ('description' in _cve) else 'n/a'
                _cveLink = _cves['link'] if ('link' in _cve) else 'n/a'
                _cveCriticality = _cves['criticity'] if ('criticity' in _cve) else 'n/a'

                # Check if CVE is already recorded for this application
                if _cveName not in singletonCVEs:
                    # Write CVE info into file
                    _bomfile.write('{},"{}","{}","{}","{}","{}",{}\n'.format(_appid, _appname, _cveName, _cveDesc, _cveLink, _cveCriticality))
                    singletonCVEs[_cveName] = True

            # Write in empty row if no CVEs were found for an application
            if len(singletonCVEs) == 0:
                _bomfile.write('{},"{}","{}","{}","{}","{}"\n'.format(_appid, _appname, 'n/a', 'n/a', 'n/a', 'n/a'))

    except Exception as e:
        print('***********************************************')
        print('Error: {}'.format(str(e)))
        print('***********************************************')
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
        _bomfile.write('app_id,app_name,cve_name,cve_link,cve_desc,cve_criticality\n') # Write file header
    
        # Get list of all applications
        _headers = {'Accept':'application/json'}
        _resturi = 'WS2/domains/{}/applications?expand='.format(_args.orgid)
    
        print('Making a call to get list of apps: {}/{}'.format(_args.connection, _resturi))
        _jsonResult = requests.get(_args.connection+'/'+_resturi, headers=_headers, auth=_auth, verify=False, timeout=10).json()
        print('Call succeeded!')
        
        # Loop through each application to get and store the BOM
        #for item in _jsonResult:
        #    print('Getting BOM for application "{}" (id:{})'.format(item['name'], item['id']))
        #    getAppBOM(_args.connection, _auth, _args.orgid, item['id'], item['name'], _bomfile)
        
        #getAppBOM(_args.connection, _auth, _args.orgid, 1246, 'ACH', _bomfile) # Debugging statement 
         
        # Close file
        _bomfile.close()
        print ('CVE information stored in file: {}'.format(_args.filepath))
        
    except Exception as e:
            print('Error: {}'.format(str(e)))

    sys.exit(0)
    