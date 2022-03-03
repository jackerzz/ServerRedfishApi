# Copyright 2016 Hewlett Packard Enterprise Development, LP.
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
from _redfishobject import RedfishObject
from redfish.rest.v1 import ServerDownOrUnreachableError

def ex40_reset_ESKM_eventlog(redfishobj):
    sys.stdout.write("\nEXAMPLE 40: Reset ESKM event logs\n")
    instances = redfishobj.search_for_type("ESKM.")

    for instance in instances:
        tmp = redfishobj.redfish_get(instance["@odata.id"])

        for action in tmp.dict["Actions"]:
            if "ClearESKMLog" in action:
                post_target = tmp.dict["Actions"][action]["target"]
        body = dict()
        if redfishobj.typepath.defs.isgen9:
            body["Action"] = "ClearESKMLog"
        else:
            body["Action"] = "HpeESKM.ClearESKMLog"

        response = redfishobj.redfish_post(post_target, body)
        redfishobj.error_handler(response)

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    # iLO_https_url = "blobstore://."
    # iLO_account = "None"
    # iLO_password = "None"

    # When running remotely connect using the iLO secured (https://) address, 
    # iLO account name, and password to send https requests
    # iLO_https_url acceptable examples:
    # "https://10.0.0.100"
    # "https://f250asha.americas.hpqcorp.net"
    iLO_https_url = "https://10.0.0.100"
    iLO_account = "admin"
    iLO_password = "password"

    # Create a REDFISH object
    try:
        REDFISH_OBJ = RedfishObject(iLO_https_url, iLO_account, iLO_password)
    except ServerDownOrUnreachableError, excp:
        sys.stderr.write("ERROR: server not reachable or doesn't support " \
                                                                "RedFish.\n")
        sys.exit()
    except Exception, excp:
        raise excp

    ex40_reset_ESKM_eventlog(REDFISH_OBJ)



