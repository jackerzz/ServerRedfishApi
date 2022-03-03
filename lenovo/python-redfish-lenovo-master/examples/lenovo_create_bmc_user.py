###
#
# Lenovo Redfish examples - Create bmc user
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


import sys
import redfish
import json
import traceback
import lenovo_utils as utils

#set user privileges
def set_custom_role_privileges(REDFISH_OBJ,response_account_service_url,roleid,authority):
    result = {}
    list_auth = []
    #check custom privileges
    rang_custom_auth = ("Supervisor","ReadOnly","UserAccountManagement","RemoteConsoleAccess","RemoteConsoleAndVirtualMediaAccess","RemoteServerPowerRestartAccess","AbilityClearEventLogs","AdapterConfiguration_Basic"
,"AdapterConfiguration_NetworkingAndSecurity","AdapterConfiguration_Advanced")
    for auth in authority:
        if auth not in rang_custom_auth:
            result = {'ret': False, 'msg': "custom privileges %s out of rang %s" %(auth, str(rang_custom_auth))}
            return result
        list_auth.append(auth)
    roles_url = response_account_service_url.dict['Roles']['@odata.id']
    response_roles_url = REDFISH_OBJ.get(roles_url, None)
    if response_roles_url.status == 200:
        max_role_num = response_roles_url.dict["Members@odata.count"]
        list_role_url = []
        for i in range(max_role_num):
            role_url = response_roles_url.dict["Members"][i]["@odata.id"]
            list_role_url.append(role_url)
        dst_role_url = ""
        for role_url in list_role_url:
            response_role_url = REDFISH_OBJ.get(role_url, None)
            if response_role_url.status == 200:
                role_username = response_role_url.dict["Name"]
                if role_username == roleid:
                    dst_role_url = role_url
                    break
            else:
                result = {'ret': False, 'msg': "response roles url Error code %s" % response_roles_url.status}
                return result
        if dst_role_url == "":
            result = {'ret': False, 'msg': "roles is not existed"}
            return result
        response_role_url = REDFISH_OBJ.get(dst_role_url, None)
        if response_role_url.status != 200:
            result = {'ret': False, 'msg': "response role url Error code %s" % response_role_url.status}
            return result
        parameter = {
            "OemPrivileges": list_auth
        }
        response_update_role_url = REDFISH_OBJ.patch(dst_role_url, body=parameter)
        if response_update_role_url.status in [200, 204]:
            result = {'ret': True, 'msg': "update role auth successful"}
            return result
        else:
            error_message = utils.get_extended_error(response_update_role_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                dst_role_url, response_update_role_url.status, error_message)}
            return result
    else:
        result = {'ret': False,
                  'msg': "response roles url Error code %s" % response_roles_url.status}
        return result


import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def set_tsm_privileges(ip, login_account, login_password, username, kvm, vm):
    """Set priviledges for kvm console and virtual media access
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: user will be granted
    :type username: string
    :params kvm: KVM console access authority
    :type kvm: int
    :params vm: virtual media access authority
    :type vm: int
    :returns: returns result with messages when succeeded or failed
    """
    login_host = "https://" + ip
    headers = {"Content-Type": "application/json"}
    session_url = login_host + "/api/session"
    body = {'username':login_account,'password':login_password}
    # Create session connection
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    s = requests.session()
    response = s.post(session_url, headers=headers, data=json.dumps(body), verify=False)
    json_response = json.loads(response.content)
    if response.status_code == 200:
        h = {"X-CSRFTOKEN": "%s" % (json_response["CSRFToken"]), "Content-Type": "application/json"}
        # Get user list and find if username exist
        user_list_url = login_host + "/api/settings/users"
        response_user_list_uri = s.get(user_list_url, headers=h, cookies=s.cookies.get_dict(), verify=False)
        user_list = json.loads(response_user_list_uri.content)
        user = None
        for member in user_list:
            if member['name'] == username:
                user = member
                break
        if user == None:
            result = {'ret': False, 'msg': "The user specified %s does not exist." % username}
            return result

        # Change kvm/vm access
        user_url = login_host + "/api/settings/users/%s" % user['userid']
        user['kvm'] = kvm
        user['vmedia'] = vm
        response_put_uri = s.put(user_url, headers=h, data=json.dumps(user), cookies=s.cookies.get_dict(), verify=False)
        if response_put_uri.status_code == 200:
            result = {'ret': True, 'msg': "Success to set KVM or VM access privileges."}
        else:
            result = {'ret': False, 'msg': "Failed to set KVM or VM access privileges, response code  %s" % response_put_uri.status_code}

        # Delete session
        delete_url = login_host + "/api/session"
        s.delete(delete_url, headers=h, cookies=s.cookies.get_dict(), verify=False)
        return result

    else:
        result = {'ret': False,
                  'msg': "Session connection failed, response code %s" % response.status_code}
        return result


def lenovo_create_bmc_user(ip, login_account, login_password, username, password, authority):
    """create bmc user
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: new  username by user specified
    :type username: string
    :params password: new password by user specified
    :type password: string
    :params authority: user authority by user specified
    :type authority: list
    :returns: returns update user password result when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get ServiceBase resource
    try:
        # Get /redfish/v1
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        # Get /redfish/v1/AccountService
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status != 200:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get /redfish/v1/AccountService/Accounts
        accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status != 200:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                accounts_url, response_accounts_url.status, error_message)}
            return result

        # Check user create mode
        create_mode = "POST_Action"
        if response_accounts_url.dict["Members@odata.count"] in [9, 12]:
             create_mode = "PATCH_Action"

        if create_mode == "POST_Action":
                # Set user privilege
                rolename = ""
                kvm_privilege = 0
                vm_privilege = 0
                if "Supervisor" in authority:
                    rolename = "Administrator"
                elif "Operator" in authority:
                    rolename = "Operator"
                elif "ReadOnly" in authority:
                    rolename = "ReadOnly"
                else:
                    rolename = authority[0]
                
                if "RemoteConsoleAccess" in authority:
                    kvm_privilege = 1
                if "RemoteConsoleAndVirtualMediaAccess" in authority:
                    kvm_privilege = 1
                    vm_privilege = 1

                #create new user account
                headers = None
                parameter = {
                    "Password": password,
                    "Name": username,
                    "UserName": username,
                    "RoleId":rolename
                }
                response_create_url = REDFISH_OBJ.post(accounts_url, body=parameter, headers=headers)
                if response_create_url.status == 200 or response_create_url.status == 201 or response_create_url.status == 204:
                    result = {'ret': True, 'msg': "create new user successful."}
                    if kvm_privilege or vm_privilege:
                        result_set = set_tsm_privileges(ip, login_account, login_password, username, kvm=kvm_privilege, vm=vm_privilege)
                        if result_set['ret'] == False:
                            result['msg'] = "create new user successful but failed to set kvm or virtual media access privileges."
                    return result
                else:
                    error_message = utils.get_extended_error(response_create_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        accounts_url, response_create_url.status, error_message)}
                    return result

        if create_mode == "PATCH_Action":
                max_account_num = response_accounts_url.dict["Members@odata.count"]
                list_account_url = []
                for i in range(max_account_num):
                    account_url = response_accounts_url.dict["Members"][i]["@odata.id"]
                    list_account_url.append(account_url)
                first_empty_account = ""
                flag = False
                user_pos = 0
                num = 0
                roleuri = ""
                #find the first empty account pos
                for account_url in list_account_url:
                    num = num + 1
                    response_accounts_url = REDFISH_OBJ.get(account_url, None)
                    if response_accounts_url.status == 200:
                        account_username = response_accounts_url.dict["UserName"]
                        if account_username == "" and flag is False:
                            first_empty_account = account_url
                            flag = True
                            user_pos = num
                            roleuri = response_accounts_url.dict["Links"]["Role"]["@odata.id"]
                        elif account_username == username:
                            result = {'ret': False, 'msg': "Username %s is existed" %username}
                            return result
                    else:
                        error_message = utils.get_extended_error(response_accounts_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            account_url, response_accounts_url.status, error_message)}
                        return result
                if first_empty_account == "":
                    result = {'ret': False, 'msg': "Accounts is full,can't create a new account"}
                    return result
                #set user privilege
                links_role = {}
                if "Supervisor" in authority or "Administrator" in authority:
                    rolename = "Administrator"
                elif "Operator" in authority:
                    rolename = "Operator"
                elif "ReadOnly" in authority:
                    rolename = "ReadOnly"
                else: # customized privilege
                    rolename = "CustomRole" + str(user_pos)
                    result = set_custom_role_privileges(REDFISH_OBJ,response_account_service_url,rolename,authority)
                    if result['ret'] == False:
                        return result
                    if rolename not in roleuri:
                        links_role = {"Role":{"@odata.id": "/redfish/v1/AccountService/Roles/"+rolename}}
                #create new user account
                response_empty_account_url = REDFISH_OBJ.get(first_empty_account, None)
                if response_empty_account_url.status != 200:
                    error_message = utils.get_extended_error(response_empty_account_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        first_empty_account, response_empty_account_url.status, error_message)}
                    return result
                if "@odata.etag" in response_empty_account_url.dict:
                    etag = response_empty_account_url.dict['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}
                if links_role:
                    parameter = {
                        "Enabled": True,
                        "Password": password,
                        "UserName": username,
                        "RoleId": rolename,
                        "Links": links_role
                        }
                else:
                    parameter = {
                        "Enabled": True,
                        "Password": password,
                        "UserName": username,
                        "RoleId": rolename
                        }
                response_create_url = REDFISH_OBJ.patch(first_empty_account, body=parameter, headers=headers)
                if response_create_url.status in [200, 204]:
                    result = {'ret': True, 'msg': "Created new user successfully"}
                    return result
                else:
                    error_message = utils.get_extended_error(response_create_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        first_empty_account, response_create_url.status, error_message)}
                    return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


import argparse
def add_helpmessage(argget):
    argget.add_argument('--newusername', type=str, required=True, help='Input name of new user')
    argget.add_argument('--newuserpasswd', type=str, required=True, help='Input password of new user')
    help_str = "This parameter specify user's privileges. "
    help_str += "You can specify 'Supervisor', 'Operator', 'ReadOnly' or other customized privileges. "
    help_str += "For customized privileges, you can choose one or more values in this list: "
    help_str += "[UserAccountManagement, RemoteConsoleAccess, RemoteConsoleAndVirtualMediaAccess, RemoteServerPowerRestartAccess, AbilityClearEventLogs, AdapterConfiguration_Basic, AdapterConfiguration_NetworkingAndSecurity, AdapterConfiguration_Advanced]"
    argget.add_argument('--authority', nargs='*', default=["Supervisor"], help=help_str)


def add_parameter():
    """Add create bmc user parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python lenovo_create_bmc_user.py -i 10.10.10.10 -u USERID -p PASSW0RD --newusername testuser --newuserpasswd Test123_pass --authority Supervisor"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["newusername"] = args.newusername
    parameter_info["newuserpasswd"] = args.newuserpasswd
    parameter_info["authority"] = args.authority
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        username = parameter_info['newusername']
        password = parameter_info['newuserpasswd']
        authority = parameter_info['authority']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # create bmc user result and check result
    result = lenovo_create_bmc_user(ip, login_account, login_password, username, password,authority)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
