# coding: utf-8
import json

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkcore.http.http_config import HttpConfig

"""
# 导入指定云服务的库 huaweicloudsdk{service}
"""
from huaweicloudsdkvpc.v2 import *

"""
# 导入其它依赖库
"""
from urllib.request import urlopen
from json import load, loads
from Crypto.Cipher import AES
import time, os, base64, sys, getopt

"""
# 导入IPy
#    --(Class and tools for handling of IPv4 and IPv6 addresses and networks)
#用于判断当前公网IP地址是IPv4 or IPv6
"""
import IPy

aes_key_from_cli = ''
ip_from_cli = ''
date_to_be_deleted = ''

"""
# 从命令行获取解密秘钥、待删除rule的创建时间等信息
"""


def start(argv):
    if not argv:
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv, "hk:d:", ["help", "key=", "date="])
    except getopt.GetoptError:
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('# HCTool-XXX.py -k <aes_key> -d <date_to_be_deleted> OR \n# HCTool-XXX.py --key=<aes_key> '
                  '--date=<date_to_be_deleted>')
            sys.exit()
        elif opt in ("-k", "--key"):
            global aes_key_from_cli
            aes_key_from_cli = arg
            if aes_key_from_cli == '':
                print({'delete_security_group_rule_tool: error@start()': 'ERROR: key must not be NULL!'})
                sys.exit(2)
            else:
                print({'delete_security_group_rule_tool: message@start()': 'key is: ' + aes_key_from_cli})
        elif opt in ("-d", "--date"):
            global date_to_be_deleted
            date_to_be_deleted = arg
            if date_to_be_deleted != '':
                print({'delete_security_group_rule_tool: message@start()': 'date to be deleted is: ' +
                                                                           date_to_be_deleted})
            else:
                print({'delete_security_group_rule_tool: error@start()': 'ERROR: date is NULL!'})
                sys.exit(2)


"""
# en_val为经过base64编码后的密文string
"""


def decrypt_env(en_val):
    (aes_key, aes_iv, aes_mode) = (aes_key_from_cli, 'knx5FQtE4XOQ', AES.MODE_GCM)
    if aes_key_from_cli == '':
        print({'create_security_group_rule_tool: error@decrypt_env()': 'ERROR: key must not be NULL!'})
        sys.exit(2)
    aes_de_instance = AES.new(aes_key.encode('utf-8'), aes_mode, aes_iv.encode('utf-8'))
    plain_val = aes_de_instance.decrypt(base64.b64decode(en_val.encode('utf-8'))).decode('utf-8')
    return plain_val


"""
# 获取个人云环境配置
# en_cred_dict = {'EN_AK':' ','EN_SK':' ','EN_ProjectID':' ','Region':' '}
"""


def get_cred_config():
    en_env_data = os.getenv('EN_CRED_JSON_STR')
    en_cred_dict = loads(en_env_data)
    en_ak = en_cred_dict['EN_AK']
    en_sk = en_cred_dict['EN_SK']
    en_project_id = en_cred_dict['EN_ProjectID']

    ak = decrypt_env(en_ak)
    sk = decrypt_env(en_sk)
    project_id = decrypt_env(en_project_id)

    region = en_cred_dict['Region']
    security_group_id = en_cred_dict['SecurityGroupID']
    endpoint = "https://" + "vpc." + region + ".myhwclouds.com"
    print({'create_security_group_rule_tool: message@get_cred_config()': 'current endpoint is: ' + endpoint})
    return ak, sk, project_id, region, endpoint, security_group_id


"""  
# demo 列出所有VPC
"""


def list_vpc(client):
    try:
        request = ListVpcsRequest()
        response = client.list_vpcs(request)
        print(response)
    except exceptions.ClientRequestException as e:
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)


"""
# demo 列出所有SecurityGroupRules
"""


def list_sg(client):
    try:
        request = ListSecurityGroupRulesRequest()
        response = client.list_security_group_rules(request)
        print(response)
    except exceptions.ClientRequestException as e:
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)


"""
# 创建放通通当前工具所在主机公网IP的安全组 
"""


def get_pub_ip_from_inet():
    ip_from_inet = ''
    for num in range(1, 3):
        if num == 1:
            ip_from_inet = load(urlopen('https://httpbin.org/ip'))['origin']
        elif num == 2:
            ip_from_inet = load(urlopen('https://api.ipify.org/?format=json'))['ip']
        else:
            ip_from_inet = load(urlopen('https://jsonip.com'))['ip']

        if IPy.IP(ip_from_inet).version() == 4:
            break

    return ip_from_inet


"""
# 删除current_rules中description包含condition的rule
"""


def delete_sg(client, security_group_id, current_rules, condition):
    rule_id = ''
    for rule in current_rules['security_group_rules']:
        if condition in rule['description']:
            rule_id = rule['id']
            print("delete: " + json.dumps(rule))
            try:
                request = DeleteSecurityGroupRuleRequest(rule_id)
                response = client.delete_security_group_rule(request)
                print(response)
            except exceptions.ClientRequestException as e:
                print(e.status_code)
                print(e.request_id)
                print(e.error_code)
                print(e.error_msg)


"""
# 列出当前所有rules
# return (字典类型)rules
"""


def list_sg(client, security_group_id):
    try:
        request = ListSecurityGroupRulesRequest()
        response = client.list_security_group_rules(request)
        # print(response.to_dict()['security_group_rules'])
        # for rule in response.to_dict()['security_group_rules']:
        #     if 'May  8' in rule['description']:
        #         print("list: " + rule['id'])
        return response.to_dict()
    except exceptions.ClientRequestException as e:
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)


if __name__ == "__main__":
    start(sys.argv[1:])

    (ak, sk, project_id, region, endpoint, security_group_id) = get_cred_config()

    config = HttpConfig.get_default_config()
    config.ignore_ssl_verification = True
    credentials = BasicCredentials(ak, sk, project_id)

    vpc_client = VpcClient.new_builder(VpcClient) \
        .with_http_config(config) \
        .with_credentials(credentials) \
        .with_endpoint(endpoint) \
        .build()

    # list_vpc(vpc_client)
    # list_sg(vpc_client)

    current_rules = list_sg(vpc_client, security_group_id)
    condition = date_to_be_deleted
    delete_sg(vpc_client, security_group_id, current_rules, condition)
