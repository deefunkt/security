# -*- coding: utf-8 -*-
"""
Created on Wed Apr 18 14:04:03 2018

@author: deefunkt
"""

from email.parser import Parser
from hashlib import sha256
from bs4 import BeautifulSoup
import re
import time
import glob


path = 'C:\\Users\\A-Sha\\Downloads\\'
messages = glob.glob(path + 'original_msg*')



class EmailParser:
    '''This class defines a way to interact with a raw email stored on disk, and parses it for:

- IP addresses related with the delivery of the message, excluding known
    'good' addresses such as prod.outlook.com, and protection.outlook.com
- Attachments and embedded files, their filenames, and sha256 hash values
- URLs embedded in the email

These artefacts are to be queried against OSINT sources eg. VirusTotal, urlscan.io
for known malicious activity.
    '''
    def __init__(self, file):
        with open(file) as fp:
            self.message = Parser().parse(fp)
        self.sender  = self.message['From']
        self.return_path = self.message['Return-Path']
        self.receiver = self.message['To']
        self.subject = self.message['Subject']

    # define more content types for greater flexibility in handling different
    # attachment types such as .docx, .xls, video files etc.
    def get_attachments(self):
        attachment_hashes = []
        for part in self.message.walk():
            content_type = part.get_content_type()
            if 'image' in content_type:
                filename = part['Content-Id'].strip("<>")
                hashval = sha256(part.get_payload(decode=True)).hexdigest()
                attachment_hashes.append([filename, hashval])
            elif 'application' in content_type:
                filename = part['Content-Id'].strip("<>")
                hashval = sha256(part.get_payload(decode=True)).hexdigest()
                attachment_hashes.append([filename, hashval])
        return attachment_hashes

    # Reverses the message structure so that the first encountered IP address is that
    # of the sender's. Returns a list of IP addresses associated with intermediate
    # routing of the message, excluding known 'good' servers.
    def get_ip_addresses(self):
        ip_addresses = []
        sender_ip_address = []
        for header in reversed(self.message._headers):
            if header[0] == "Received":
                if 'protection.outlook.com' not in header[1] and 'prod.outlook.com' not in header[1]:
                    p = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                    for address in p.findall(header[1]):
                        ip_addresses.append(address)
                    sender_ip_address = ip_addresses[0]
        return sender_ip_address, ip_addresses

    def get_urls(self):
        url_list = []
        for part in self.message.walk():
            content_type = part.get_content_type()
            if 'html' in content_type:
                soup = BeautifulSoup(part.get_payload(decode=True), 'html.parser')
                urls = [link.get('href') for link in soup.find_all('a')]
                for url in urls:
                    url_list.append(url)
        return url_list


if __name__ == '__main__':
        
    p = EmailParser(messages[5])
    print("From: ", p.sender)
    print("Return Path", p.return_path)
    print("To: ", p.receiver)
    print("Subject: " + p.subject)
    attachments = p.get_attachments()
    urls = p.get_urls()
    sender, ip_addresses = p.get_ip_addresses()


    # known bad file hash
    bad_hash = '67c3c3a72115570e6f6a609dbf6f115aa2031fa1ef540742e3ece81776cbe72a'
    # known bad IP
    bad_ip = '90.156.201.27'
    # known bad URL
    bad_url = 'http://www.faceboak.net'


    '''
    URLSCAN.IO API USAGE
    '''

    import urlscanio
    urlscanner = urlscanio.UrlScanner()
    result = urlscanner.search('121.130.17.230', type='ip', return_type='domain')
    result = urlscanner.search(ip_addresses[1], type='ip', return_type='countries')
    ip_report = urlscanner.submitURL(urls[0])
    ip_report = urlscanner.scanResult(ip_report['api'])

    # bulk submit and scan
    submissions = urlscanner.submitBulk(urls)
    results, malicious = urlscanner.scanBulk(submissions)

    # known bad items
    ip_report = urlscanner.submitURL(bad_url)
    ip_report = urlscanner.scanResult(ip_report['api'])



    '''
    VIRUSTOTAL API USAGE
    '''

    from vtanalysis import VTScanner
    # Single url report
    vtscanner = VTScanner()
    vt_url_report = [urls[0], vtscanner.get_url_report(urls[0])]
    bad_urls, bad_files, domains = vtscanner.get_ip_report(sender)

    # known malicious
    bad_urls, bad_files, domains = vtscanner.get_ip_report(bad_ip)
    malware = vtscanner.get_file_report(bad_hash, timeout=3)
    report = [bad_url, vtscanner.get_url_report(bad_url)]

    # For bulk queries of urls, we are allowed 4 requests per minute
    vt_url_report = []
    for url in urls:
        vt_url_report.append([url, vtscanner.get_url_report(url)])
        time.sleep(15)


    '''
    MISCELLANEOUS
    '''

    for msg in messages:
        p = EmailParser(msg)
        print("From: ", p.sender)
        print("To: ", p.receiver)
        print("Subject: ", p.subject)
        print(p.return_path)
    #    print(p.get_urls())
