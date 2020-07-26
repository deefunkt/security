# -*- coding: utf-8 -*-
"""
Created on Wed Apr 18 10:04:03 2018

@author: deefunkt

"""

import requests


class VirusTotalScanner:
    '''This class contains methods for interacting with the VirusTotal public API.
 - Urls can be checked against the database, and submitted for scanning.
 - IP addresses can be submitted, and associated bad hostnames and file hashes previously identified by
     virustotal are returned as a measure of threat.
'''
    def __init__(self, key = ''):
        self.key = key
        self.url = 'https://www.virustotal.com/vtapi/v2'

    def isError(self, status):
        if status != 200:
            if status == 204:
                print('Rate limit exceeded.')
            elif status == 400:
                print('Bad request')
            elif status == 403:
                print('Forbidden - are you trying to use Private API functions?')
            else:
                print('Unknown Error - ' + str(status))
            return True
        else:
            return False

    def getUrlReport(self, url, scan = 0):
        '''This method will return 0 if the URL is marked safe by everyone.
        If even one source reports it as malicious, the full result dictionary will be returned.
        '''
        result = 0
        payload = {'apikey' : self.key,
                   'resource' : url,
                   'scan' : scan,}
        response = requests.get(url=self.url+'/url/report', params = payload)
        if not self.isError(response.status_code):
            response = response.json()
            if response['response_code'] == 0:
                if scan == 0:
                    print('Item not present in database. Consider submitting.')
                elif scan == 1:
                    print('Item submitted for scanning, check later at:')
                    print(response['permalink'])
            elif response['response_code'] == -2:
                print('Item being processed. Please try again later.')
            elif response['response_code'] == 1:
                print('Scan Finished for ' + url)
            else:
                print('Something went wrong. Response_code is - '+ response['response_code'])
            if response['positives'] == 0:
                print(url + ' is safe according to VirusTotal contributors.')
            else:
                print('Malicious url - '+ url)
                result = []
                for engine in [*response['scans']]:
                    if response['scans'][engine]['detected'] == True:
#                        import pdb; pdb.set_trace()
                        result.append(str(engine) + ' - ' + str(response['scans'][engine]['result']))
        return result

    def submitURL(self, url):
        '''This method returns the link where the report can later be consumed.
        Alternatively we can use the api again later to query for the malicious URL
        '''        
        payload = {'apikey' : self.key,
                   'resource' : url}
        response = requests.get(url=self.url+'/url/scan', params = payload)
        if not self.isError(response.status_code):
            print(response.json()['verbose_msg'])
            return response.json(['permalink'])

    
    def getIPReport(self, ip_address):
        '''This method takes in a IPv4 address and returns two lists.
The first shows malicious hostnames associated with the IP address, and has the format:
    ```python
        [element i] = "Resolved: [URL associated with IP address]
                    detected by [some fraction] of engines"
    ```
    The second contains hashes for malicious files that have previously been correlated with the IP address.
    ```python
        [element i] = "Associated file: [sha256 hash]
                    detected by [some fraction] of engines"
    ```
        '''
        result = 0
        malicious_files = 0
        payload = {'ip' : ip_address,
                   'apikey': self.key}
        response = requests.get(url=self.url + '/ip-address/report', params = payload)
        if not self.isError(response.status_code):
            response = response.json()
            if response['response_code'] == -1:
                print('Invalid IP address submitted.')
            elif response['response_code'] == 0:
                print('VirusTotal has no information on IP address: ' + str(ip_address))
            else:
                # list comprehension saves us from creating and appending to a list inside for loops
                malicious_files = ['Associated file: "' + file['sha256'] +
                               '" \ndetected by ' +
                               str(file['positives']) + '/' + str(file['total']) + ' engines'
                               for file in response['detected_downloaded_samples']]
                result = ['Resolved: "' + detection['url'] + '"\ndetected by ' +
                          str(detection['positives']) + '/' + str(detection['total']) + ' engines'
                          for detection in response['detected_urls']]
        return result, malicious_files

if __name__ == '__main__':
    # Test Cases for VirusTotalScanner
    vtscanner = VirusTotalScanner()
    # 'result' contains a list of engines and malware identifications.
    result = vtscanner.getUrlReport('http://www.faceboak.net')
    result, bad_files = vtscanner.getIPReport('90.156.201.27')
