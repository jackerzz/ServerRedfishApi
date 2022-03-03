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

def get_schema(restobj, schema_prefix):
    sys.stdout.write("\nEXAMPLE 27:  Find and return schema " + \
                                                        schema_prefix + "\n")
    response = restobj.get("/rest/v1/Schemas")

    for schema in response.dict["Items"]:
        if schema["Schema"].startswith(schema_prefix):
            for location in schema["Location"]:
                extref_uri = location["Uri"]["extref"]
                response = restobj.get(extref_uri)
                if response.status == 200:
                    sys.stdout.write("\tFound " + schema_prefix + " at " + extref_uri + "\n")
                    return
                else:
                    sys.stderr.write("\t" + schema_prefix + " not found at " + extref_uri + "\n")
                    return

    sys.stderr.write("Registry " + schema_prefix + " not found.\n")

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
    get_schema(REST_OBJ, "ComputerSystem")
    REST_OBJ.logout()
