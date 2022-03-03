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

def get_ilo_ip(restobj):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "Manager." in instance.Type:
                manager_path = instance.href
                break

    response = restobj.get(manager_path)
    ethernet_rsp =  restobj.get(response.dict["links"]["EthernetNICs"]["href"])
    for item in ethernet_rsp.dict["Items"]:
        if not item["IPv4Addresses"][0]["Address"] == "0.0.0.0":
            sys.stdout.write("\t" + item["IPv4Addresses"][0]["Address"] + "\n")
    sys.stdout.write("%s" % response)

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # While this example can be run remotely, it is used locally to locate the
    # iLO IP address
    SYSTEM_URL = None
    LOGIN_ACCOUNT = None
    LOGIN_PASSWORD = None

    # When running remotely connect using the iLO secured (https://) address,
    # iLO account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    # SYSTEM_URL = "https://10.0.0.100"
    # LOGIN_ACCOUNT = "admin"
    # LOGIN_PASSWORD = "password"

    #Create a REST object
    REST_OBJ = LegacyRestClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD)
    REST_OBJ.login()
    sys.stdout.write("\nEXAMPLE 52: Get iLO IP locally\n")
    get_ilo_ip(REST_OBJ)
    REST_OBJ.logout()
