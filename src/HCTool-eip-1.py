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
from json import loads
from Crypto.Cipher import AES
import os, base64, sys, getopt

"""
# 导入IPy
#    --(Class and tools for handling of IPv4 and IPv6 addresses and networks)
#用于判断当前公网IP地址是IPv4 or IPv6
"""
# import IPy

tool_function = "EIP Tool"

aes_key_from_cli = ''
ip_from_cli = ''
date_to_be_deleted = ''
bandwidth_size = ''
operation = ''
bandwidth_name = "tempEip"

"""
# 从命令行获取解密秘钥、待删除rule的创建时间等信息
"""


def start(argv):
    if not argv:
        print('Get usage info by # HCTool-XXX.py -h')
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv, "hk:b:o:", ["help", "key=", "bandwidth=", "operation="])
    except getopt.GetoptError:
        print('Get usage info by # HCTool-XXX.py -h')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('# HCTool-XXX.py -k <aes_key> -o <operation: add or delete> -b <bandwidth_size> OR \n'
                  '# HCTool-XXX.py --key=<aes_key> --operation=<operation: add or delete> --bandwidth=<bandwidth_size>')
            sys.exit()
        elif opt in ("-k", "--key"):
            global aes_key_from_cli
            aes_key_from_cli = arg
            console_log("INFO", start.__name__, "key is: " + aes_key_from_cli, None)
        elif opt in ("-o", "--operation"):
            global operation
            operation = arg
            if operation != "add" and operation != "delete":
                console_log("ERROR", start.__name__, "operation must not be add or delete!", None)
                sys.exit(2)
            console_log("INFO", start.__name__, "operation is: " + operation, None)
        elif opt in ("-b", "--bandwidth"):
            global bandwidth_size
            bandwidth_size = arg
            if bandwidth_size != '':
                console_log("INFO", start.__name__, 'bandwidth to be created is: ' + bandwidth_size + 'M', None)
            else:
                bandwidth_size = 5
                console_log("INFO", start.__name__, '(DEFAULT)bandwidth to be created is: ' + bandwidth_size + 'M', None)

    if aes_key_from_cli == '':
        console_log("ERROR", start.__name__, "key must not be NULL!", None)
        sys.exit(2)
    if operation == '':
        console_log("ERROR", start.__name__, "operation must not be NULL!", None)
        sys.exit(2)


"""
# en_val为经过base64编码后的密文string
"""


def decrypt_env(en_val):
    (aes_key, aes_iv, aes_mode) = (aes_key_from_cli, 'knx5FQtE4XOQ', AES.MODE_GCM)
    if aes_key_from_cli == '':
        console_log("ERROR", decrypt_env.__name__, "key must not be NULL!", None)
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
    console_log("INFO", get_cred_config.__name__, 'current region is: ' + region, None)
    return ak, sk, project_id, region, endpoint, security_group_id


def console_log(log_level, log_location, log_str_content, log_object_content):
    if log_level is None:
        log_level = "DEFAULT"
    if log_location is None:
        log_location = "NOT PROVIDED"
    else:
        log_location += "()"
    if log_object_content is not None:
        print("--" + tool_function + "- " + log_level + "@" + log_location + ": ")
        if log_str_content is not None:
            print(log_str_content)
        print(log_object_content)
        print("----\n")
    else:
        if log_str_content is not None:
            print("--" + tool_function + "-- " + log_level + "@" + log_location + ": " + log_str_content)
            print("----\n")


def sdk_exception_log(log_location, log_object_content):
    log_level = "EXCEPTION"
    if log_location is None:
        log_location = "NOT PROVIDED"
    else:
        log_location += "()"
    print("--" + tool_function + "- " + log_level + "@" + log_location + ": ")
    print("status_code: ")
    print(log_object_content.status_code)
    print("request_id: ")
    print(log_object_content.request_id)
    print("error_code: ")
    print(log_object_content.error_code)
    print("error_msg: ")
    print(log_object_content.error_msg)
    print("----\n")


"""
# 根据命令行获取的带宽大小创建临时EIP
# return EIP对象字典
"""


def create_temp_eip(eip_client, bandwidth_size):
    size = bandwidth_size
    global bandwidth_name
    try:
        eip = CreatePublicipOption(type="5_bgp")
        bandwidth = CreatePublicipBandwidthOption(name=bandwidth_name, size=size, charge_mode="bandwidth",
                                                  share_type="PER")
        body = CreatePublicipRequestBody(bandwidth=bandwidth, publicip=eip)
        request = CreatePublicipRequest(body)
        response = eip_client.create_publicip(request)
        console_log("INFO", create_temp_eip.__name__, "Create API response: ", response)
        return response.to_dict()
    except exceptions.ClientRequestException as e:
        sdk_exception_log(create_temp_eip.__name__, e)


"""
# 删除临时EIP（当前不支持指定删除对象）
"""


def delete_temp_eip(eip_client, bandwidth_name):
    temp_eip_id = get_temp_eip(eip_client, bandwidth_name)
    if temp_eip_id is not None:
        console_log("INFO", delete_temp_eip.__name__, "ID to be deleted: "+ temp_eip_id, None)
        try:
            request = DeletePublicipRequest()
            request.publicip_id = temp_eip_id
            response = client.delete_publicip(request)
            console_log("INFO", delete_temp_eip.__name__, "Delete API response: ", response)
        except exceptions.ClientRequestException as e:
            sdk_exception_log(delete_temp_eip.__name__, e)
    else:
        console_log("ERROR", delete_temp_eip.__name__, "there is not a temp eip!", None)


"""
# 根据临时EIP的bandwidth_name获取EIP ID
# return 临时EIP的ID
"""


def get_temp_eip(eip_client, bandwidth_name):
    try:
        request = ListPublicipsRequest()
        response = eip_client.list_publicips(request)
        console_log("INFO", get_temp_eip.__name__, "List API response: ", response)
        eip_list = response.to_dict()
        for eip_item in eip_list['publicips']:
            if eip_item['bandwidth_name'] == bandwidth_name:
                temp_eip_id = eip_item['id']
                console_log("INFO", get_temp_eip.__name__, "ID of " + bandwidth_name + " is : " + temp_eip_id, None)
                return temp_eip_id
    except exceptions.ClientRequestException as e:
        sdk_exception_log(get_temp_eip.__name__, e)


if __name__ == "__main__":
    start(sys.argv[1:])

    (ak, sk, project_id, region, endpoint, security_group_id) = get_cred_config()

    credentials = BasicCredentials(ak, sk, project_id)
    config = HttpConfig.get_default_config()
    config.ignore_ssl_verification = False

    client = EipClient.new_builder() \
        .with_http_config(config) \
        .with_credentials(credentials) \
        .with_region(EipRegion.value_of(region)) \
        .build()

    if operation == 'add':
        temp_eip = create_temp_eip(client, bandwidth_size)
        console_log("INFO", __name__, 'temp eip address is: ' + temp_eip['publicip']['public_ip_address'], None)
    elif operation == "delete":
        delete_temp_eip(client, bandwidth_name)
