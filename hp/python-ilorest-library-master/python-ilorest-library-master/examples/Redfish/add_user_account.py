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
An example of adding a user account by iLO privileges or redfish standard roles
"""

import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
global DISABLE_RESOURCE_DIR

from ilorest_util import get_resource_directory
from ilorest_util import get_gen

def add_ilo_user_account(_redfishobj, new_loginname, new_username, new_password, role_id, \
                         privilege_dict):
    resource_instances = get_resource_directory(_redfishobj)

    if DISABLE_RESOURCE_DIR or not resource_instances:
        #resource directory is not available so we will navigate through paths manually to obtain
        #account info
        account_service_uri = _redfishobj.root.obj['AccountService']['@odata.id']
        account_service_response = _redfishobj.get(account_service_uri)
        account_collection_uri = account_service_response.obj['Accounts']['@odata.id']
        #Add via role id
        body = {"RoleId": role_id}
    else:
        #obtain all account instances from resource directory
        for instance in resource_instances:
            if '#ManagerAccountCollection.' in instance['@odata.type']:
                account_collection_uri = instance['@odata.id']
        body = {"Oem": {"Hpe": {"Privileges": {}}}}
        #HPE server, so add via privileges
        for priv in privilege_dict:
            body["Oem"]["Hpe"]["Privileges"][priv] = privilege_dict[priv]
        #Add login name
        body["Oem"]["Hpe"]["LoginName"] = new_loginname

    #Fill in the rest of the payload
    body["UserName"] = new_username
    body["Password"] = new_password

    #We pass the URI and the dictionary as a POST command (part of the redfish object)
    resp = _redfishobj.post(account_collection_uri, body)

    #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
    #error message to see what went wrong
    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, sort_keys=True))
        except Exception:
            sys.stderr.write("A response error occurred, unable to access iLO Extended Message "\
                             "Info...")
    elif not resp.status in [200, 201]:
        sys.stderr.write("An http response of '%s' was returned.\n" % resp.status)
    else:
        print("Success!\n")
        print(json.dumps(resp.dict, indent=4, sort_keys=True))

def add_ilo_user_account_gen9(_redfishobj, new_loginname, new_username, new_password):
	
	account_collection_uri = "/redfish/v1/AccountService/Accounts/"
	#Add via gen9 priv dic
	body = {'Oem': {'Hp': {'Privileges': {"LoginPriv": True, "RemoteConsolePriv": True,
        "UserConfigPriv": True, "VirtualMediaPriv": True, "VirtualPowerAndResetPriv": True,
        "iLOConfigPriv": True}, 'LoginName': new_loginname}},'UserName': new_username, 'Password': new_password}
	#We pass the URI and the dictionary as a POST command (part of the redfish object)
	resp = _redfishobj.post(account_collection_uri, body)
	print(json.dumps(resp.dict, indent=4, sort_keys=True))

if __name__ == "__main__":

    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.0"
    # "https://ilo.hostname"
    if len(sys.argv) == 4:
        # Remote mode
        SYSTEM_URL = sys.argv[1]
        LOGIN_ACCOUNT = sys.argv[2]
        LOGIN_PASSWORD = sys.argv[3]
    else:
        # Local mode
        SYSTEM_URL = None
        LOGIN_ACCOUNT = None
        LOGIN_PASSWORD = None

    #account login name (iLO GUI actually considers this to be 'UserName', but
    #this is the redfish standard username)
    ACCOUNT_LOGIN_NAME = "batman"

    #account user name (iLO GUI actually considers this to be 'LoginName', but
    #this is the redfish login)
    ACCOUNT_USER_NAME = "bruce_wayne"

    #account password
    ACCOUNT_PASSWORD = "thedarkknight123"

    #A predefined role for the user, (The redfish standard method for accounts).
    #This is a translated to a pre-configured arrangement of privileges on HPE servers
    ROLE_ID = "Administrator" #Administrator, ReadOnly or Operator are available

    #Dictionary of modifiable privileges for HPE servers (modify this if you wish to directly set
    #an account with specific privileges
    PRIVILEGE_DICT = {"iLOConfigPriv": True, "VirtualMediaPriv": True, "RemoteConsolePriv": True,\
                      "UserConfigPriv": True, "VirtualPowerAndResetPriv": True, \
                      "SystemRecoveryConfigPriv": True, "LoginPriv": True, \
                      "HostStorageConfigPriv": True, "HostNICConfigPriv": True, \
                      "HostBIOSConfigPriv": True}
    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = False

    ca_cert_data = {}
    ca_cert_data["cert_file"] = "c:\\test\\ppcacuser.crt"
    ca_cert_data["key_file"] = "c:\\test\\ppcacuserpriv.key"
    ca_cert_data["key_password"] = "password"
    LOGIN_ACCOUNT = None
    LOGIN_PASSWORD = None

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD, ca_cert_data=ca_cert_data)
        #REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, ca_cert_data=ca_cert_data)
        # Login with the Redfish client
        if ca_cert_data is None:
            REDFISHOBJ.login()
        else:
            REDFISHOBJ.login(auth='certificate')
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    #obtain all account instances, by navigating set paths and keys to find the relevant URI
    #(account_collection_uri, accounts, rd) = get_accounts(redfishobj, DISABLE_RESOURCE_DIR)
    #print("\n\nShowing accounts before changes:\n\n")
    #show_accounts(redfishobj, accounts)

    #if account_collection_uri and accounts:
    #add specified account
    (ilogen,_) = get_gen(REDFISHOBJ)
    print ("Generation is ", ilogen)
    if int(ilogen) == 5:
        add_ilo_user_account(REDFISHOBJ,ACCOUNT_LOGIN_NAME,ACCOUNT_USER_NAME,ACCOUNT_PASSWORD,ROLE_ID,PRIVILEGE_DICT)
    else:
        add_ilo_user_account_gen9(REDFISHOBJ,ACCOUNT_LOGIN_NAME,ACCOUNT_USER_NAME,ACCOUNT_PASSWORD)
    REDFISHOBJ.logout()
