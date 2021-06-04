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
import os, base64, sys, getopt, time

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
bandwidth_name = 'tempEip'
server_port_id = ''
server_name_key = 'ecs-hk'
original_eip_id = ''

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
            print('# HCTool-XXX.py -k <aes_key> -o <operation: add or delete or list or default> '
                  '-b <bandwidth_size> OR \n'
                  '# HCTool-XXX.py --key=<aes_key> --operation=<operation: add or delete or list or default> '
                  '--bandwidth=<bandwidth_size>')
            sys.exit()
        elif opt in ("-k", "--key"):
            global aes_key_from_cli
            aes_key_from_cli = arg
            console_log("INFO", start.__name__, "key is: " + aes_key_from_cli, None)
        elif opt in ("-o", "--operation"):
            global operation
            operation = arg
            if operation != "add" and operation != "delete" and operation != "list" and operation != "default":
                console_log("ERROR", start.__name__, "operation must not be add or delete or list!", None)
                sys.exit(2)
            console_log("INFO", start.__name__, "operation is: " + operation, None)
        elif opt in ("-b", "--bandwidth"):
            global bandwidth_size
            bandwidth_size = arg
            if bandwidth_size != '':
                console_log("INFO", start.__name__, 'bandwidth to be created is: ' + bandwidth_size + 'M', None)
            else:
                bandwidth_size = 5
                console_log("INFO", start.__name__, '(DEFAULT)bandwidth to be created is: ' + bandwidth_size + 'M',
                            None)

    if aes_key_from_cli == '':
        console_log("ERROR", start.__name__, "key must not be NULL!", None)
        sys.exit(2)
    if operation == 'add' or operation == 'default':
        if bandwidth_size == '':
            bandwidth_size = 5
    if operation == '':
        # 默认进行创建指定带宽大小的temp EIP，并绑定到server上
        operation = 'default'
        console_log("INFO", start.__name__, "operation will be set to default: " + operation, None)
        if bandwidth_size == '':
            bandwidth_size = 5


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
        console_log("INFO", delete_temp_eip.__name__, "ID to be deleted: " + temp_eip_id, None)
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
        # request = ListPublicipsRequest()
        # response = eip_client.list_publicips(request)
        response = list_all_eip(eip_client)
        # console_log("INFO", get_temp_eip.__name__, "List API response: ", response)
        eip_list = response.to_dict()
        temp_eip_id = None
        for eip_item in eip_list['publicips']:
            if eip_item['bandwidth_name'] == bandwidth_name:
                temp_eip_id = eip_item['id']
                console_log("INFO", get_temp_eip.__name__, "ID of " + bandwidth_name + " is : " + temp_eip_id, None)
                return temp_eip_id
        console_log("ERROR", get_temp_eip.__name__, "there is not a temp eip!", None)
        return temp_eip_id
    except exceptions.ClientRequestException as e:
        sdk_exception_log(get_temp_eip.__name__, e)


"""
# 获取原EIP IP
# return 原EIP IP
"""


def get_original_eip(eip_client):
    global server_name_key
    global original_eip_id
    try:
        response = list_all_eip(eip_client)
        eip_list = response.to_dict()
        for eip_item in eip_list['publicips']:
            if server_name_key in eip_item['bandwidth_name']:
                original_eip_id = eip_item['id']
                console_log("INFO", get_original_eip.__name__, "ID of original EIP is : " + original_eip_id, None)
                return original_eip_id
        console_log("ERROR", get_original_eip.__name__, "get original EIP failed!", None)
        return original_eip_id
    except exceptions.ClientRequestException as e:
        sdk_exception_log(get_temp_eip.__name__, e)


"""
# 获取ecs server的port id，用于后续解绑、绑定EIP
# return port id
"""


def get_server_port_id(eip_client):
    global server_port_id
    try:
        response = list_all_eip(eip_client)
        eip_list = response.to_dict()
        for eip_item in eip_list['publicips']:
            if eip_item['port_id'] is not None:
                server_port_id = eip_item['port_id']
                console_log("INFO", get_server_port_id.__name__, "Server's port ID is : " + server_port_id, None)
                return server_port_id
        console_log("ERROR", get_server_port_id.__name__, "get server port ID failed!", None)
        return server_port_id
    except exceptions.ClientRequestException as e:
        sdk_exception_log(get_server_port_id.__name__, e)


"""
# 获取ecs server的当前的EIP name
# return EIP name
"""


def get_current_eip(eip_client):
    try:
        response = list_all_eip(eip_client)
        eip_list = response.to_dict()
        current_eip_name = None
        for eip_item in eip_list['publicips']:
            if eip_item['port_id'] is not None:
                current_eip_name = eip_item['bandwidth_name']
                console_log("INFO", get_current_eip.__name__, "Current EIP name is : " + current_eip_name, None)
                return current_eip_name
        return current_eip_name
    except exceptions.ClientRequestException as e:
        sdk_exception_log(get_server_port_id.__name__, e)


"""
# 列出当前所有EIP
# return: instance of ListPublicipsResponse
"""


def list_all_eip(eip_client):
    try:
        request = ListPublicipsRequest()
        response = eip_client.list_publicips(request)
        console_log("INFO", list_all_eip.__name__, "List API response: ", response)
        return response
    except exceptions.ClientRequestException as e:
        sdk_exception_log(list_all_eip.__name__, e)


"""
# 更新server EIP至新申请的temp EIP，前提是temp EIP已经创建
# return temp EIP address
"""


def update_server_eip(eip_client):
    global bandwidth_name
    global original_eip_id
    global server_port_id
    original_eip_id = get_original_eip(eip_client)
    server_port_id = get_server_port_id(eip_client)
    temp_eip_id = get_temp_eip(eip_client, bandwidth_name)
    if temp_eip_id is None:
        console_log("INFO", update_server_eip.__name__, "Now there is not a temp EIP!"
                                                        " A new EIP will be created after 5 seconds", None)
        wait(5)
        temp_eip = create_temp_eip(client, bandwidth_size)
        temp_eip_id = temp_eip['publicip']['id']
        console_log("INFO", update_server_eip.__name__, 'temp eip address is: ' +
                    temp_eip['publicip']['public_ip_address'], None)

    # 解绑当前EIP
    try:
        request = UpdatePublicipRequest()
        request.publicip_id = original_eip_id
        update_option = UpdatePublicipOption()
        request.body = UpdatePublicipsRequestBody(
            publicip=update_option
        )
        response = client.update_publicip(request)
        console_log("INFO", update_server_eip.__name__, "Unbind original EIP\nUpdate API response: ", response)
    except exceptions.ClientRequestException as e:
        sdk_exception_log(update_server_eip.__name__, e)

    # 绑定temp EIP
    try:
        request = UpdatePublicipRequest()
        request.publicip_id = temp_eip_id
        update_option = UpdatePublicipOption(port_id=server_port_id)
        request.body = UpdatePublicipsRequestBody(
            publicip=update_option
        )
        response = client.update_publicip(request)
        console_log("INFO", update_server_eip.__name__, "Bind temp EIP\nUpdate API response: ", response)
        # print(response.to_dict()['publicip']['public_ip_address'])
        console_log("INFO", update_server_eip.__name__, "You can use the temp IP to reconnect: " +
                    response.to_dict()['publicip']['public_ip_address'], None)
    except exceptions.ClientRequestException as e:
        sdk_exception_log(update_server_eip.__name__, e)


"""
# 更新server EIP至新申请的temp EIP，前提是temp EIP已经创建
# return temp EIP address
"""


def recover_server_eip(eip_client):
    global bandwidth_name
    global original_eip_id
    global server_port_id
    server_port_id = get_server_port_id(eip_client)
    temp_eip_id = get_temp_eip(eip_client, bandwidth_name)
    original_eip_id = get_original_eip(eip_client)

    # 解绑当前EIP
    try:
        request = UpdatePublicipRequest()
        request.publicip_id = temp_eip_id
        update_option = UpdatePublicipOption()
        request.body = UpdatePublicipsRequestBody(
            publicip=update_option
        )
        response = client.update_publicip(request)
        console_log("INFO", recover_server_eip.__name__, "Unbind temp EIP\nUpdate API response: ", response)
    except exceptions.ClientRequestException as e:
        sdk_exception_log(recover_server_eip.__name__, e)

    # 绑定原 EIP
    try:
        request = UpdatePublicipRequest()
        request.publicip_id = original_eip_id
        update_option = UpdatePublicipOption(port_id=server_port_id)
        request.body = UpdatePublicipsRequestBody(
            publicip=update_option
        )
        response = client.update_publicip(request)
        console_log("INFO", recover_server_eip.__name__, "Bind original EIP\nUpdate API response: ", response)
    except exceptions.ClientRequestException as e:
        sdk_exception_log(recover_server_eip.__name__, e)


def wait(second):
    for i in range(0, second):
        time.sleep(1)
        print(second - i)


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
        if get_current_eip(client) == "tempEip":
            recover_server_eip(client)
        delete_temp_eip(client, bandwidth_name)
        list_all_eip(client)
    elif operation == "list":
        list_all_eip(client)
    elif operation == 'default':
        update_server_eip(client)
