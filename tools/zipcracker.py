# -*- coding: utf-8 -*-
"""
Created on Fri Sep 27 11:11:24 2019

@author: sharmay
"""

import argparse
import logging
import zipfile


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d',"archive", help="The archive to crack, currently only zip supported.")
    parser.add_argument('-w',"wordlist", help="The wordlist to use for cracking")
    parser.add_argument('-v','verbose', help='Increase verbosity of output', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        l = logging.get_logger(__name__)
        l.basicConfig(level=logging.DEBUG)
    return (args.archive, args.wordlist)


if __name__ == '__main__':
    (archive, wordlist) = parse_arguments()
    l = logging.getLogger(__name__)
    archive = zipfile.ZipFile(archive)
    wordlist = open(wordlist)
    for word in wordlist.readlines():
        word = word.strip('\n')
        l.debug('Trying password "{}"'.format(word))
        try:
            archive.extractall(pwd=word)
            l.info("Password found to be '{}'".format(word))
            exit()
        except:
            pass
    l.info('Archive not cracked with wordlist.')