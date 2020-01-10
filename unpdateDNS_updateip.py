# coding=utf-8
import requests
import os
import time
import random
import operator
import hashlib
import hmac
import base64
import json
import socket
import sys

reload(sys)  # for python2
sys.setdefaultencoding('utf8')  # for python2

# MacOS: ifconfig en0 | grep autoconf\ secured | awk '{print $2}'
# 群晖：ifconfig ovs_eth0 | grep Global | awk '{print $3}' | cut -d "/" -f 1

SecretId = "AKIDGNGvMb2NyLYY7VJcKn32qPmvve9QtKyR"
SecretKey = "bBiATelIZuEMTkw0ztgJm8FGAwgFagXA"
ServerURL = "https://cns.api.qcloud.com/v2/index.php"
recordId = '378333492'
domin = "zhiyigo.cn"
recoed_name = '默认'
subDomain = 'mail'
random.seed(time.time())

# output = os.popen("ifconfig ovs_eth0 | grep Global | awk '{print $3}' | cut -d '/' -f 1")
# output = os.popen("ifconfig en0 | grep autoconf\ secured | awk '{print $2}'")
ip_body = requests.get("http://ip.42.pl/raw")
ip_string = ip_body.text
ip_string = str(ip_string[0:len(ip_string)])
ip_string = ip_string.strip()

print ip_string


def sign(dictionary):
    sorted_dict = sorted(dictionary.items(), key=operator.itemgetter(0), reverse=False)
    option_list = []
    for k, v in sorted_dict:
        option_list.append(k + "=" + str(v))
    req_string = '&'.join(option_list)
    raw_string = "GETcns.api.qcloud.com/v2/index.php?" + req_string
    print(raw_string)
    signature = base64.b64encode(
        hmac.new(
            SecretKey.encode('utf-8'),
            raw_string.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
    ).decode('utf-8')
    # print(signature)
    return signature



# 默认
#
modify_domain_options = {
    'Timestamp': int(time.time()),
    'Nonce': random.randint(1, 999999999),
    'SecretId': SecretId,
    'SignatureMethod': 'HmacSHA256',

    'Action': 'RecordModify',
    'domain': domin,
    'recordId': recordId,
    'subDomain': subDomain,
    'recordType': 'A',
    'recordLine': recoed_name,

    'value': ip_string
}
print modify_domain_options


modify_domain_options["Signature"] = sign(modify_domain_options)

r = requests.get(ServerURL, params=modify_domain_options)
# print(r.url)
print(r.json())
responseJson = r.json()

print(json.dumps(responseJson, encoding='utf-8', ensure_ascii=False))
