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
import json
from redfish import LegacyRestClient
from get_resource_directory import get_resource_directory

def get_ESKM(restobj):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "HpESKM." in instance.Type:
                eskm_path = instance.href
                break

    response = restobj.get(eskm_path)

    sys.stdout.write("\tPrimaryKeyServerAddress:  " +
                     json.dumps(response.dict["PrimaryKeyServerAddress"]) + "\n")
    sys.stdout.write("\tPrimaryKeyServerPort:  " +
                     json.dumps(response.dict["PrimaryKeyServerPort"]) + "\n")
    sys.stdout.write("\tSecondaryKeyServerAddress:  " +
                     json.dumps(response.dict["SecondaryKeyServerAddress"])\
                      + "\n")
    sys.stdout.write("\tSecondaryKeyServerPort:  " +
                     json.dumps(response.dict["SecondaryKeyServerPort"])\
                      + "\n")
    sys.stdout.write("\tType:  " + json.dumps(response.dict["Type"]) + "\n")
    sys.stdout.write("\tKeyServerRedundancyReq:  " +
                     json.dumps(response.dict["KeyServerRedundancyReq"]) + "\n")

    sys.stdout.write("\tAccountGroup:  " + json.dumps(response.dict["KeyManagerConfig"]\
                                ["AccountGroup"]) + "\n")
    sys.stdout.write("\tESKMLocalCACertificateName:  " +
                     json.dumps(response.dict["KeyManagerConfig"]\
                                ["ESKMLocalCACertificateName"]) + "\n")
    sys.stdout.write("\tImportedCertificateIssuer:  " +
                     json.dumps(response.dict["KeyManagerConfig"]\
                                ["ImportedCertificateIssuer"]) + "\n")

    sys.stdout.write("\tESKMEvents:  " + json.dumps(response.dict["ESKMEvents"]) + "\n")

    tmp = response.dict["ESKMEvents"]
    for entry in tmp:
        sys.stdout.write("\tTimestamp : " + entry["Timestamp"] + "Event:  " +
                         json.dumps(entry["Event"]) + "\n")
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
    LOGIN_ACCOUNT =  "admin"
    LOGIN_PASSWORD =  "password"

    # Create a REST object
    REST_OBJ = LegacyRestClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, password=LOGIN_PASSWORD)
    REST_OBJ.login()
    sys.stdout.write("\nEXAMPLE 42: Get ESKM configuration\n")
    get_ESKM(REST_OBJ)
    REST_OBJ.logout()


