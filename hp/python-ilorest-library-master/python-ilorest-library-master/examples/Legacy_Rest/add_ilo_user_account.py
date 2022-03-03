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
 

"""
An example of adding a user account by iLO privileges
"""


import sys
from redfish import LegacyRestClient
from get_resource_directory import get_resource_directory

def add_ilo_user_account(restobj, new_ilo_loginname, new_ilo_username, \
                                 new_ilo_password, irc=False, cfg=False, \
                                 virtual_media=False, usercfg=False, vpr=False):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "Collection." in instance.Type:
                if instance.MemberType.startswith("ManagerAccount."):
                    accounts_path = instance.href
                    break

    body = {"UserName": new_ilo_loginname, "Password": new_ilo_password, "Oem": {}}
    body["Oem"]["Hp"] = {}
    body["Oem"]["Hp"]["LoginName"] = new_ilo_username
    body["Oem"]["Hp"]["Privileges"] = {}
    body["Oem"]["Hp"]["Privileges"]["RemoteConsolePriv"] = irc
    body["Oem"]["Hp"]["Privileges"]["iLOConfigPriv"] = cfg
    body["Oem"]["Hp"]["Privileges"]["VirtualMediaPriv"] = virtual_media
    body["Oem"]["Hp"]["Privileges"]["UserConfigPriv"] = usercfg
    body["Oem"]["Hp"]["Privileges"]["VirtualPowerAndResetPriv"] = vpr

    response = restobj.post(accounts_path, body)

    sys.stdout.write("%s" % response)

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
    sys.stdout.write("\nEXAMPLE 10: Create an iLO User Account\n")
    add_ilo_user_account(REST_OBJ, "name", "username", "password")
    REST_OBJ.logout()
