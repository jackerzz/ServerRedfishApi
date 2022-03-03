###
#
# Lenovo Redfish examples - enable user
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


def enable_bmc_user(ip, login_account, login_password, username):
    """enable user
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: Specify the BMC user name to be enabled.
    :type usernmame: None or string

    :returns: returns enable user result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Create a REDFISH object
        # Connect using the BMC address, account name, and password
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get response_base_url resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get account service url
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
                response_base_url.status, error_message)}
            return result

        # Get AccountService resource
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status == 200:
            accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get url accounts resource
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status == 200:
            account_count = response_accounts_url.dict["Members@odata.count"]

            # Loop the BMC user list and get all the bmc username
            for x in range(0, account_count):
                account_x_url = response_accounts_url.dict["Members"][x]["@odata.id"]
                response_account_x_url = REDFISH_OBJ.get(account_x_url, None)
                if response_account_x_url.status == 200:
                    bmc_username = response_account_x_url.dict['UserName']

                    # Enable the BMC user when the specified BMC username is in the BMC user list.
                    if bmc_username == username:
                        Enabled = response_account_x_url.dict['Enabled']
                        if Enabled is True:
                            result = {'ret': True, 'msg': "BMC user %s is already enabled" % username}
                            return result
                        # Set the body info
                        if "@odata.etag" in response_account_x_url.dict:
                            etag = response_account_x_url.dict['@odata.etag']
                        else:
                            etag = ""
                        headers = {"If-Match": etag}
                        parameter = {"Enabled": True, "UserName": username}

                        response_enable_user = REDFISH_OBJ.patch(account_x_url, body=parameter, headers=headers)
                        if response_enable_user.status in [200,204]:
                            result = {'ret': True, 'msg': "BMC User %s enable successfully" %username}
                            return result
                        else:
                            error_message = utils.get_extended_error(response_enable_user)
                            result = {'ret': False,
                                      'msg': "Enabled BMC user failed, url '%s' response Error code %s \nerror_message: %s" % (
                                      account_x_url, response_enable_user.status, error_message)}
                            return result
                else:
                    error_message = utils.get_extended_error(response_account_x_url)
                    result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    account_x_url, response_account_x_url.status, error_message)}
                    return result
            result = {'ret': False,
                  'msg': "Specified BMC username doesn't exist. Please check whether the BMC username is correct."}
        else:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False,
                  'msg': "Url '%s' response error code %s \nerror_message: %s" % (accounts_url,
                                                                                  response_accounts_url.status,
                                                                                  error_message)}
    except Exception as e:
        traceback.print_exc()
        result = {'ret':False, 'msg':"error message %s" %e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_parameter():
    """Add enable user id parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--username', type=str, required=True, help='Input the set enable BMC user name')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    if args.username is not None:
        parameter_info["username"] = args.username
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    username = parameter_info['username']

    # Get enable user result and check result
    result = enable_bmc_user(ip, login_account, login_password, username)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
