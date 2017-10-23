#!/usr/bin/env python3
import hashlib
import requests
from os import listdir
from os.path import isfile, join
import time
import magic
import subprocess
import json
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests import get

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_API_KEY = '34751253f8c43db28363df33a48c3995880d62aefbe5a0a7ba63ccc016da15a3'
DIR_PATH = '/home/vsmysle/selected_malware/'
JOTTI_URL = 'https://virusscan.jotti.org/en-US/search/hash/'
HYBRIDANALYSIS_URL = 'https://www.hybrid-analysis.com/api/scan/'
HYBRID_API_KEY = '5w9wolw3fyko8oks4wggc0kow'
HYBRID_SECRET = '56f96bae659f045671514f852bbc587bea08dc6d9c09988b'


def get_general_info(filename):
    output = '*'*(len(filename)+9)+'\n'
    output += '=' * (len(filename) + 9) + '\n'
    output += 'filename:%s\n' % filename
    output += '\t md5:%s\n' % (hashsum(filename, function=hashlib.md5()))
    output += '\t sha1:%s\n' % (hashsum(filename, function=hashlib.sha1()))
    output += '\t sha256:%s\n' % (hashsum(filename, function=hashlib.sha256()))
    output += '\t filetype:%s\n' % magic.from_file(DIR_PATH+filename)
    output += '=' * (len(filename) + 9) + ''
    return output


def get_hybrid_analysis_report(filehash):
    s = requests.session()
    headers = {'User-Agent': 'VxStream'}
    response = get(url='https://www.hybrid-analysis.com/api/scan/%s' % filehash,
                                auth=HTTPBasicAuth(HYBRID_API_KEY,
                                                   HYBRID_SECRET),
                                headers=headers)
    print(response.json())
    return



def get_hybrid_analysis_output(response):
    output = 'Hybrid-Analysis results:\n'
    output += '\n'
    output += '\n'


def hashsum(filename, function=hashlib.sha256()):
    with open(DIR_PATH+filename, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            function.update(data)
        f.close()
        return function.hexdigest()


def get_virustotal_report(file_hash, file_name):
    try:
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        response = requests.get(VIRUSTOTAL_URL, params=params).json()
        #time.sleep(15)
        if response['response_code'] == 0:
            up_params = {'apikey': VIRUSTOTAL_API_KEY}
            files = {'file': (file_name, open(DIR_PATH+file_name, 'rb'))}
            response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, params=up_params).json()
            time.sleep(15)
            params['resource'] = response['scan_id']
            response = requests.get(VIRUSTOTAL_URL, params=params).json()
    except Exception:
        raise Exception
    print(response)
    return response


def get_virustotal_output(responce):
    output = 'VirusTotal results:\n'
    output += '\t - permalink: %s\n' % responce['permalink']
    output += '\t - positives/ total: %d / %d\n' % (responce['positives'], responce['total'])
    output += '\t - result: %s - %s\n' % ('F-Secure', responce['scans']['F-Secure']['result'])
    return output


def get_jotti_responce(filehash):
    response = requests.get(JOTTI_URL+filehash)
    soup = BeautifulSoup(response.text, "html.parser")
    detected = soup.find("td", {'class': 'statusText'}).text
    print(detected)


def get_readpe_output(filename):
    output = 'PE Analysis:\n'
    try:
        readpe_json = json.loads(subprocess.check_output(['readpe', '--format=json', '--all', DIR_PATH+filename])
                                 .decode('utf-8'), strict=False)
        dos_header = readpe_json['DOS Header']
        imported_functions = readpe_json['Imported functions']
        output += "DOS Header\n"
        for i in dos_header:
            output += '\t%s+:%s\n' % (i, dos_header[i])
        output += "Imported functions:\n"
        for i in imported_functions:
            output += '\t - %s,\n' % (i['Name'])
        return output
    except subprocess.SubprocessError:
        return 'This file is not in PE format.'


def main():
    files = [f for f in listdir(DIR_PATH) if isfile(join(DIR_PATH, f))]
    for file in files:
        print(file)
        #print(get_general_info(file))
        #print(get_readpe_output(file))
        hahssum = hashsum(file)
        get_hybrid_analysis_report(hahssum)
        #print(get_hybrid_analysis_output(out))

        #get_jotti_responce(hashsum(file))
        #out = get_virustotal_report(hashsum(file), file)
        #print(get_virustotal_output(out))

        #time.sleep(15.1)
        #print("="*(len(file)+9)+'\n')

if __name__ == '__main__':
    main()