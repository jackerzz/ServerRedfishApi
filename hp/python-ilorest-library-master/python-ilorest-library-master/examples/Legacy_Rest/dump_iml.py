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

def dump_iml(restobj):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "LogService." in instance.Type:
                if instance["href"].endswith("IML"):
                    IML_path = instance.href
                    break

        tmp = restobj.get(IML_path)

        for entry in tmp.dict["links"]["Entries"]:
            response = restobj.get(entry["href"])
            print_log_entries(response.dict["Items"])

            while 'NextPage' in response.dict["links"]:
                response = restobj.get(entry["href"] + '?page=' + \
                            str(response.dict["links"]['NextPage']['page']))
                print_log_entries(response.dict["Items"])

def print_log_entries(log_entries):
    for log_entry in log_entries:
        sys.stdout.write(log_entry["Severity"] + ": Class " + \
             str(log_entry["Oem"]["Hp"]["Class"]) + \
             " / Code " + str(log_entry["Oem"]["Hp"]["Code"]) + \
             ":\t" + log_entry["Message"] + "\n")

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
    sys.stdout.write("\nEXAMPLE 22: Dump Integrated Management Log\n")
    dump_iml(REST_OBJ)
    REST_OBJ.logout()
