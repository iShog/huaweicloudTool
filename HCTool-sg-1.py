# coding: utf-8
from huaweicloudsdkcore.auth.credentials import BasicCredentials, GlobalCredentials
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

aes_key_from_cli = ''
ip_from_cli = ''

"""
# 从命令行获取解密秘钥、指定的IP地址等信息
"""
def start(argv):
    if (argv == []):
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)
    
    try:
        opts, args = getopt.getopt(argv, "hk:i:", ["help", "key=", "ip="])
    except getopt.GetoptError:
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('# HCTool-XXX.py -k <aes_key> -i <ip_addr> OR HCTool-XXX.py --key=<aes_key> --ip=<ip_addr>')
            sys.exit()
        elif opt in ("-k", "--key"):
            global aes_key_from_cli
            aes_key_from_cli = arg
            if (aes_key_from_cli == ''):
                print({'create_security_group_rule_tool: message@start()': 'ERROR: key must not be NULL!'})
                sys.exit(2)
            else:
                print({'create_security_group_rule_tool: message@start()': 'key is: ' + aes_key_from_cli})
        elif opt in ("-i", "--ip"):
            global ip_from_cli
            ip_from_cli = arg
            if (ip_from_cli != ''):
                print({'create_security_group_rule_tool: message@start()': 'ip addr is: ' + ip_from_cli})
            else:
                print({'create_security_group_rule_tool: message@start()': 'ERROR: ip is NULL!'})
                sys.exit(2)
"""
# en_val为经过base64编码后的密文string
"""
def decrypt_env(en_val):
    (aes_key, aes_iv, aes_mode) = (aes_key_from_cli, 'knx5FQtE4XOQ', AES.MODE_GCM)
    if (aes_key_from_cli == ''):
        print({'create_security_group_rule_tool: message@decrypt_env()': 'ERROR: key must not be NULL!'})
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
    return (ak, sk, project_id, region, endpoint, security_group_id)

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
def create_sg(client, security_group_id):

    global ip_from_cli
    cur_ip = ip_from_cli
    if (cur_ip == ''):
        cur_ip = load(urlopen('https://jsonip.com'))['ip']
        print({'create_security_group_rule_tool: message@create_sg()': 'current public network IP is: ' + cur_ip})
    
    loca_ltime = time.asctime(time.localtime(time.time()))
    
    try:
        rule = CreateSecurityGroupRuleOption(\
            security_group_id, \
            description = loca_ltime, \
            direction = "ingress", \
            remote_ip_prefix= cur_ip + "/32")
        body = CreateSecurityGroupRuleRequestBody(rule)
        request = CreateSecurityGroupRuleRequest(body)
        response = client.create_security_group_rule(request)
        print(response)
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

    #list_vpc(vpc_client)
    #list_sg(vpc_client)
    create_sg(vpc_client, security_group_id)