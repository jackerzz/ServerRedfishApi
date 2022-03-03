 # Copyright 2020 Hewlett Packard Enterprise Development LP
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

# -*- coding: utf-8 -*-
"""
An example of retrieving bios settings
"""

import sys
import json
import argparse
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
global DISABLE_RESOURCE_DIR
from ilorest_util import get_resource_directory
from ilorest_util import get_gen

def get_bios_setting(_redfishobj):

    bios_uri = None
    bios_data = None
    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        systems_uri = _redfishobj.root.obj['Systems']['@odata.id']
        systems_response = _redfishobj.get(systems_uri)
        systems_members_uri = next(iter(systems_response.obj['Members']))['@odata.id']
        systems_members_response = _redfishobj.get(systems_members_uri)
        bios_uri = systems_members_response.obj['Bios']['@odata.id']
        bios_data = _redfishobj.get(bios_uri)
    else:
        #Use Resource directory to find the relevant URI
        for instance in resource_instances:
            if '#Bios.' in instance['@odata.type']:
                bios_uri = instance['@odata.id']
                bios_data = _redfishobj.get(bios_uri)
                break

    if bios_data:
        print("\n\nShowing bios attributes before changes:\n\n")
        print(json.dumps(bios_data.dict, indent=4, sort_keys=True))

def get_bios_setting_gen9(_redfishobj):

    bios_uri = "/redfish/v1/systems/1/bios"
    bios_data = None
    #Use Resource directory to find the relevant URI
    bios_data = _redfishobj.get(bios_uri)

    if bios_data:
        print("\n\nShowing bios attributes before changes:\n\n")
        print(json.dumps(bios_data.dict, indent=4, sort_keys=True))


if __name__ == "__main__":
    # Initialize parser
    parser = argparse.ArgumentParser(description = "Script to upload and flash NVMe FW")

    parser.add_argument(
        '-i',
        '--ilo',
        dest='ilo_ip',
        action="store",
        help="iLO IP of the server",
        default=None)
    parser.add_argument(
        '-u',
        '--user',
        dest='ilo_user',
        action="store",
        help="iLO username to login",
        default=None)
    parser.add_argument(
        '-p',
        '--password',
        dest='ilo_pass',
        action="store",
        help="iLO password to log in.",
        default=None)

    options = parser.parse_args()

    system_url = "https://" + options.ilo_ip
    print (system_url)

    DISABLE_RESOURCE_DIR = False

    try:
        # Create a Redfish client object
        redfish_obj = RedfishClient(base_url=system_url, username=options.ilo_user, password=options.ilo_pass)
        # Login with the Redfish client
        redfish_obj.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()
    (ilogen,_) = get_gen(redfish_obj)
    print ("Generation is ", ilogen)
    if int(ilogen) == 5:
        get_bios_setting(redfish_obj)
    else:
        get_bios_setting_gen9(redfish_obj)
    redfish_obj.logout()
