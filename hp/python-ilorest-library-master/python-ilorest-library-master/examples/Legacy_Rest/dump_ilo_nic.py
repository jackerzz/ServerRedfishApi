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

def dump_ilo_nic(restobj):
    resource_instances = get_resource_directory(restobj)
    if resource_instances:
        #Get URI from resource directory
        for instance in resource_instances:
            if "Manager." in instance.Type:
                manager_path = instance.href
                break

    manager = restobj.get(manager_path)
    response = restobj.get(manager.dict["links"]["EthernetNICs"]["href"])

    for nic in response.dict["Items"]:
        if nic["Status"]["State"] == "Enabled":
            sys.stdout.write("\t" + nic["Name"] + "\n")

            if "MacAddress" not in nic:
                sys.stderr.write("\tNo MacAddress information available (no"
                       " 'MacAddress' property in NIC resource)\n")
            else:
                sys.stdout.write("\tMAC: " + str(nic["MacAddress"]) + "\n")

            sys.stdout.write("\tSpeed: " + str(nic["SpeedMbps"]) + "\n")
            sys.stdout.write("\tAutosense:  " + str(nic["Autosense"]) + "\n")
            sys.stdout.write("\tFull Duplex:  " + str(nic["FullDuplex"]) + "\n")
            if "FQDN" not in nic:
                sys.stderr.write("\tNo FQDN information available\n")
            else:
                sys.stdout.write("\tFQDN:  " + str(nic["FQDN"]) + "\n")
            for addr in nic["IPv4Addresses"]:
                sys.stdout.write("\tIPv4 Address:  " + addr["Address"]
                       + " from " + addr["AddressOrigin"] + "\n")
            if "IPv6Addresses" not in nic:
                sys.stderr.write("\tIPv6Addresses information not "\
                                                            "available\n")
            else:
                for addr in nic["IPv6Addresses"]:
                    sys.stdout.write("\tIPv6 Address:  " + addr["Address"]
                           + " from " + addr["AddressOrigin"] + "\n")
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
    sys.stdout.write("\nEXAMPLE 13: Get iLO NIC state\n")
    dump_ilo_nic(REST_OBJ)
    REST_OBJ.logout()
