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

def set_ilo_timezone(restobj, olson_timezone):
    sys.stdout.write("\tNOTE: This only works if iLO is NOT configured to " \
                                    "take time settings from DHCP v4 or v6\n")
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "HpiLODateTime." in instance.Type:
                datetime_path = instance.href
                break

    response = restobj.get(datetime_path)

    for timezone in response.dict["TimeZoneList"]:
        if timezone["Name"].startswith(olson_timezone):
            body = {"TimeZone": {"Name": timezone["Name"]}}
            response = restobj.patch(datetime_path, body)
            sys.stdout.write("%s" % response)
            break

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
    SYSTEM_URL = "https://16.83.63.89"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    #Create a REST object
    REST_OBJ = LegacyRestClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD)
    REST_OBJ.login()
    sys.stdout.write("\nEXAMPLE 28: Set iLO's Timezone\n")
    set_ilo_timezone(REST_OBJ, "America/Chicago")
    REST_OBJ.logout()
