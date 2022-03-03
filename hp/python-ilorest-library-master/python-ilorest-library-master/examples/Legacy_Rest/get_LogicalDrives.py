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

def get_LogicalDrives(restobj):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "Collection.1.0.0" in instance.Type:
                if "HpSmartStorageArrayController." in instance.MemberType:
                    array_controllers = instance.href
                    break
    collection = restobj.get(array_controllers)
    for instance in collection.obj.links.Member:
        controller = restobj.get(instance.href)
        sys.stdout.write("Location: %s\n" % controller.obj.Location)
        logicaldrivecollection = restobj.get(controller.obj.links.LogicalDrives.href)
        for logicaldrive in logicaldrivecollection.obj.links.Member:
            drive = restobj.get(logicaldrive.href)
            sys.stdout.write("\t%s\n" % json.dumps(drive.dict))

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
    sys.stdout.write("\nEXAMPLE 44: Dump LogicalDrive details\n")
    REST_OBJ.login()
    get_LogicalDrives(REST_OBJ)
    REST_OBJ.logout()
