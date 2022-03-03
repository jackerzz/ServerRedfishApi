 # Copyright 2016 Hewlett Packard Enterprise Development LP
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

def ex10_add_ilo_user_account(redfishobj, new_ilo_loginname, new_ilo_username, \
                                 new_ilo_password, irc=None, cfg=None, \
                                 virtual_media=None, usercfg=None, vpr=None):
    sys.stdout.write("\nEXAMPLE 10: Create an iLO User Account\n")
    instances = redfishobj.search_for_type("AccountService.")

    for instance in instances:
        rsp = redfishobj.redfish_get(instance["@odata.id"])

        body = {"UserName": new_ilo_loginname, "Password": \
                                                new_ilo_password, "Oem": {}}
        OemHpDict = {}
        OemHpDict["LoginName"] = new_ilo_username
        OemHpDict["Privileges"] = {}
        OemHpDict["Privileges"]["RemoteConsolePriv"] = irc
        OemHpDict["Privileges"]["iLOConfigPriv"] = cfg
        OemHpDict["Privileges"]["VirtualMediaPriv"] = virtual_media
        OemHpDict["Privileges"]["UserConfigPriv"] = usercfg
        OemHpDict["Privileges"]["VirtualPowerAndResetPriv"] = vpr
        if redfishobj.typepath.defs.isgen9:
            body["Oem"]["Hp"] = OemHpDict
        else:
            body["Oem"]["Hpe"] = OemHpDict

        newrsp = redfishobj.redfish_post(rsp.dict["Accounts"]["@odata.id"], \
                                                                        body)
        redfishobj.error_handler(newrsp)

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

    ex10_add_ilo_user_account(REDFISH_OBJ, "name", "username", "password")
  