# coding: utf-8

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkeip.v2 import *
from huaweicloudsdkeip.v2.region.eip_region import EipRegion

"""
# 导入其它依赖库
"""
# from urllib.request import urlopen
from json import load, loads
from Crypto.Cipher import AES
import time, os, base64, sys, getopt

"""
# 导入IPy
#    --(Class and tools for handling of IPv4 and IPv6 addresses and networks)
#用于判断当前公网IP地址是IPv4 or IPv6
"""
# import IPy

aes_key_from_cli = ''
ip_from_cli = ''
date_to_be_deleted = ''
bandwidth_size = ''
operation = ''
eip_name = "tempEip"

"""
# 从命令行获取解密秘钥、待删除rule的创建时间等信息
"""


def start(argv):
    if not argv:
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv, "hk:b:o:", ["help", "key=", "bandwidth=", "operation="])
    except getopt.GetoptError:
        print('Get useage info by # HCTool-XXX.py -h')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('# HCTool-XXX.py -k <aes_key> -o <operation: add or delete> -b <bandwidth_size> OR \n'
                  '# HCTool-XXX.py --key=<aes_key> --operation=<operation: add or delete> --bandwidth=<bandwidth_size>')
            sys.exit()
        elif opt in ("-k", "--key"):
            global aes_key_from_cli
            aes_key_from_cli = arg
            if aes_key_from_cli == '':
                print({'eip_tool: error@start()': 'ERROR: key must not be NULL!'})
                sys.exit(2)
            else:
                print({'eip_tool: message@start()': 'key is: ' + aes_key_from_cli})
        elif opt in ("-o", "--operation"):
            global operation
            operation = arg
            if operation == '':
                print({'eip_tool: error@start()': 'ERROR: operation must not be NULL!'})
                sys.exit(2)
            else:
                print({'eip_tool: message@start()': 'operation is: ' + operation})
        elif opt in ("-b", "--bandwidth"):
            global bandwidth_size
            bandwidth_size = arg
            if bandwidth_size != '':
                print({'eip_tool: message@start()': 'bandwidth to be created is: ' +
                                                    bandwidth_size})
            else:
                bandwidth_size = 5
                print({'eip_tool: message@start()': '(DEFAULT)bandwidth to be created is: ' +
                                                    bandwidth_size})


"""
# en_val为经过base64编码后的密文string
"""


def decrypt_env(en_val):
    (aes_key, aes_iv, aes_mode) = (aes_key_from_cli, 'knx5FQtE4XOQ', AES.MODE_GCM)
    if aes_key_from_cli == '':
        print({'eip_tool: error@decrypt_env()': 'ERROR: key must not be NULL!'})
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
    print({'eip_tool: message@get_cred_config()': 'current region is: ' + region})
    # print({'create_security_group_rule_tool: message@get_cred_config()': 'current endpoint is: ' + endpoint})
    return ak, sk, project_id, region, endpoint, security_group_id


def create_temp_eip(eip_client, bandwidth_size):
    size = bandwidth_size
    try:
        eip = CreatePublicipOption(type="5_bgp")
        bandwidth = CreatePublicipBandwidthOption(name="tempEip", size=size, charge_mode="bandwidth", share_type="PER")
        body = CreatePublicipRequestBody(bandwidth=bandwidth, publicip=eip)
        request = CreatePublicipRequest(body)
        response = eip_client.create_publicip(request)
        print(response)
        return response.to_dict()
    except exceptions.ClientRequestException as e:
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)


def delete_temp_eip(eip_client, eip_name):
    print("...")


if __name__ == "__main__":
    start(sys.argv[1:])

    (ak, sk, project_id, region, endpoint, security_group_id) = get_cred_config()

    credentials = BasicCredentials(ak, sk, project_id)
    config = HttpConfig.get_default_config()
    config.ignore_ssl_verification = True

    client = EipClient.new_builder() \
        .with_http_config(config) \
        .with_credentials(credentials) \
        .with_region(EipRegion.value_of(region)) \
        .build()

    if operation == 'add':
        temp_eip = create_temp_eip(client, bandwidth_size)
        print({'eip_tool: message@main()': 'temp eip address is: ' + temp_eip['publicip']['public_ip_address']})
    elif operation == "delete":
        delete_temp_eip(client, eip_name)

