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

def set_bios_uefi_shell_startup(restobj, uefienabled="Enabled", \
                                     networkpath="", urlpath="", \
                                     bios_password=None):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "HpBios." in instance.Type:
                if "PUT" in instance.HttpMethods:
                    bios_path = instance.href
                    break

    #BIOS password is the password if secondary authentication is 
    #required before entering RBSU screen Only required on Gen9 systems
    restobj.bios_password = bios_password
    body = dict()
    body["UefiShellStartup"] = uefienabled
    body["UefiShellStartupLocation"] = networkpath
    body["UefiShellStartupUrl"] = urlpath

    response = restobj.patch(bios_path, body)
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
    set_bios_uefi_shell_startup(REST_OBJ, "Enabled", "10.0.0.0", "test.com")
    REST_OBJ.logout()
