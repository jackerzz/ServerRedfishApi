 # Copyright 2020 Hewlett Packard Enterprise Development LP
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

# -*- coding: utf-8 -*-
"""
An example of modifying a user account
"""

import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

from get_resource_directory import get_resource_directory

def modify_ilo_user_account(_redfishobj, username_to_modify, new_loginname, new_username, \
                         new_password, role_id, privilege_dict):

    account_collection_uri = None

    resource_instances = get_resource_directory(_redfishobj)

    if DISABLE_RESOURCE_DIR or not resource_instances:
        #resource directory is not available so we will navigate through paths manually to obtain
        #account info
        account_service_uri = _redfishobj.root.obj['AccountService']['@odata.id']
        account_service_response = _redfishobj.get(account_service_uri)
        account_collection_uri = account_service_response.obj['Accounts']['@odata.id']
        #modify role id
        if role_id:
            body = {"RoleId": role_id}
    else:
        #obtain all account instances from resource directory
        for instance in resource_instances:
            if '#ManagerAccountCollection.' in instance['@odata.type']:
                account_collection_uri = instance['@odata.id']
        if privilege_dict:
            #HPE server, so modify privileges
            body = {"Oem": {"Hpe": {"Privileges": {}}}}
            for priv in privilege_dict:
                body["Oem"]["Hpe"]["Privileges"][priv] = privilege_dict[priv]
        if new_loginname:
            #modify login name
            body["Oem"]["Hpe"]["LoginName"] = new_loginname

    if new_username:
        body["UserName"] = new_username
    if new_password:
        body["Password"] = new_password

    #find the account to modify
    account_uri_to_modify = None
    account_uris = REDFISHOBJ.get(account_collection_uri)
    for account_uri in account_uris.dict['Members']:
        account = REDFISHOBJ.get(account_uri['@odata.id'])
        if account.dict['UserName'] == username_to_modify:
            account_uri_to_modify = account_uri['@odata.id']
            break

    if not account_uri_to_modify:
        sys.stderr.write("Cannot find account to modify")
        return

    #modify the account
    resp = REDFISHOBJ.patch(account_uri_to_modify, body)

    #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
    #error message to see what went wrong
    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended Message "\
                             "Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of '%s' was returned.\n" % resp.status)
    else:
        print("Success!\n")
        print(json.dumps(resp.dict, indent=4, sort_keys=True))

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://10.0.0.100"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    #username of the account to modify
    USERNAME_TO_MODIFY = "bruce_wayne"

    #account login name to change the account to
    NEW_LOGINNAME = "joker"

    #account user name to change the account to
    NEW_USERNAME = "joker"

    #account password to change the account to
    NEW_PASSWORD = "joker123"

    #role to change account to
    ROLE_ID = "ReadOnly" #Administrator, ReadOnly or Operator are available

    #update HPE account privileges
    PRIVILEGE_DICT = {"iLOConfigPriv": False, "VirtualMediaPriv": False, "RemoteConsolePriv": True,\
                      "UserConfigPriv": False, "VirtualPowerAndResetPriv": False, \
                      "SystemRecoveryConfigPriv": False, "LoginPriv": True, \
                      "HostStorageConfigPriv": False, "HostNICConfigPriv": False, \
                      "HostBIOSConfigPriv": False}
    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = False

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    modify_ilo_user_account(REDFISHOBJ, USERNAME_TO_MODIFY, NEW_LOGINNAME, NEW_USERNAME, \
                            NEW_PASSWORD, ROLE_ID, PRIVILEGE_DICT)

    REDFISHOBJ.logout()
