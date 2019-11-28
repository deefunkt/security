# -*- coding: utf-8 -*-
"""
Created on Mon Apr 16 11:23:21 2018

@author: deefunkt

This file contains an interface to urlscan.io
"""
# TODO: implement urlscan.io search method - atm, results are weird and not relevant

import requests
import time



class UrlScanner:
    '''This class contains methods for querying urls against urlscan.io.

    Typical uses:
    ```python
        scanner = urlScanner()
        submission = scanner.submitUrl(url="http://www.google.com")
        result, isMalicious = scanner.scanResult(scanid = submission["api"])
    'result' contains a dictionary containing various artefacts about the URL.
    'malicious' is 1 for yes and 0 for not.
    You can also supply a list of urls, and will obtain a list of results (dicts) and malicious (list)
        submissions = scanner.submitBulk(urls)
        results, malicious = scanner.scanBulk(submissions)
    ```
    '''
    def __init__(self, key=""):
        # api key built in to use key by default
        self.key = key
        self.scanurl = "https://urlscan.io/api/v1/scan/"

    def submitURL(self, url, public=False):
        headers = { 'Content-Type' : 'application/json',
                    'API-Key': self.key,
                }
        data = '{"url" : "%s"}' %url
        response = requests.post(self.scanurl, headers = headers, data = data).json()
        print(response["message"] + ' - ' + url)
        return response

    def search(self, query, type, return_type='domains'):
        url = 'https://urlscan.io/api/v1/search/'
        if type == 'ip':
            data = {'q': 'ip:"' + query+'"'}
        elif type == 'hash':
            data = {'q': 'hash:'  + query}
        elif type == 'domain':
            data = {'q': 'domain:'  + query}
        response = requests.get(url, params=data, timeout=3)
        if return_type == 'countries':
            # below line creates a list of countries, gets the unique values then returns a list.
            return list(set([r['page']['country'] for r in response.json()['results']]))
        else:
            return list(set([r['page']['domain'] for r in response.json()['results']]))

    def scanResult(self, scanid):
        ready = False
        retries = 0
        malicious = 0
        while not ready and retries < 10: #no rate limit for result querying
            response = requests.get(scanid, timeout=3)
            retries += retries
            if response.status_code != 404:
                ready = True
            else:
                time.sleep(1)

        if retries > 9:
            print('Max retry limit reached, please check the api code.')
        elif response.status_code == 400:
            print("Unable to resolve domain: ")
        else:
            response = response.json()
            malicious = response['stats']['malicious']
        if malicious:
            print('Malicious URL found - ' + response['page']['url'])
        return response, malicious

    def submitBulk(self, urls, public=False):
        submissions = []
        for url in urls:
            submissions.append(self.submitURL(url, public))
            time.sleep(2) # for rate limit by urlscan.io
        return submissions

    def scanBulk(self, submissions):
        results = []
        malicious = []
        for submission in submissions:
            print('Fetching scan for - ' + submission['url'])
            result, mal = self.scanResult(submission['api'])
            results.append(result)
            malicious.append(mal)
        return results, malicious

# TEST CASES
#scanner = UrlScanner()
#submission = scanner.submitURL(url="http://www.google.com")
#result, malicious = scanner.scanResult(scanid=submission['api'])
#
#urls = ['http://www.google.com','http://www.youtube.com','https://www.python.org']
#submissions = scanner.submitBulk(urls)
#results, malicious = scanner.scanBulk(submissions)
