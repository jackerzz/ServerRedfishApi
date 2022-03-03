 # Copyright 2020 Hewlett Packard Enterprise Development, LP.
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

import sys
from redfish import LegacyRestClient
from get_resource_directory import get_resource_directory

def modify_ilo_user_account(restobj, ilo_login_name_to_modify, \
                new_ilo_loginname, new_ilo_username, new_ilo_password, \
                irc=None, cfg=None, virtual_media=None, usercfg=None, vpr=None):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "Collection." in instance.Type:
                if "ManagerAccount." in instance.MemberType:
                    accounts_path = instance.href
                    break
    accounts = restobj.get(accounts_path)
    for account in accounts.obj.Items:
        for account in accounts.dict["Items"]:
            if account["UserName"] == ilo_login_name_to_modify:
                body = {}
                body_oemhp = {}
                body_oemhp_privs = {}

                # if new loginname or password specified
                if new_ilo_password:
                    body["Password"] = new_ilo_password
                if new_ilo_loginname:
                    body["UserName"] = new_ilo_loginname

                # if different username specified
                if new_ilo_username:
                    body_oemhp["LoginName"] = new_ilo_username

                # if different privileges were requested (None = no change)
                if irc != None:
                    body_oemhp_privs["RemoteConsolePriv"] = irc
                if virtual_media != None:
                    body_oemhp_privs["VirtualMediaPriv"] = virtual_media
                if cfg != None:
                    body_oemhp_privs["iLOConfigPriv"] = cfg
                if usercfg != None:
                    body_oemhp_privs["UserConfigPriv"] = usercfg
                if vpr != None:
                    body_oemhp_privs["VirtualPowerAndResetPriv"] = vpr

                # component assembly
                if len(body_oemhp_privs):
                    body_oemhp["Privileges"] = body_oemhp_privs
                if len(body_oemhp):
                    body["Oem"] = {"Hp": body_oemhp}

                newrsp = restobj.patch(account["links"]["self"]["href"], body)
                sys.stdout.write("%s" % newrsp)
                return

    sys.stderr.write("Account not found\n")

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # SYSTEM_URL = None
    # LOGIN_ACCOUNT = None
    # LOGIN_PASSWORD = None

    # When running remotely connect using the iLO secured (https://) address,
    # iLO account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://10.0.0.100"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    #Create a REST object
    REST_OBJ = LegacyRestClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD)
    REST_OBJ.login()
    sys.stdout.write("\nEXAMPLE 11: Modify an iLO user account\n")
    modify_ilo_user_account(REST_OBJ, "name", "newname", "newusername", "newpassword")
    REST_OBJ.logout()
