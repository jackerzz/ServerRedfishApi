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
An example of gathering the Logical Drives on an HPE iLO system
"""

import sys
import json
import argparse
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
from ilorest_util import get_resource_directory
from ilorest_util import get_gen

def get_SmartArray_LogicalDrives(_redfishobj):

    smartstorage_response = []
    smartarraycontrollers = dict()

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        systems_uri = _redfishobj.root.obj['Systems']['@odata.id']
        systems_response = _redfishobj.get(systems_uri)
        systems_members_uri = next(iter(systems_response.obj['Members']))['@odata.id']
        systems_members_response = _redfishobj.get(systems_members_uri)
        smart_storage_uri = systems_members_response.obj.Oem.Hpe.Links\
                                                                ['SmartStorage']['@odata.id']
        smart_storage_arraycontrollers_uri = _redfishobj.get(smart_storage_uri).obj.Links\
                                                                ['ArrayControllers']['@odata.id']
        smartstorage_response = _redfishobj.get(smart_storage_arraycontrollers_uri).obj['Members']
    else:
        for instance in resource_instances:
            #Use Resource directory to find the relevant URI
            if '#HpeSmartStorageArrayControllerCollection.' in instance['@odata.type']:
                smartstorage_uri = instance['@odata.id']
                print (smartstorage_uri)
                smartstorage_response = _redfishobj.get(smartstorage_uri).obj['Members']
                break

    for controller in smartstorage_response:
        smartarraycontrollers[controller['@odata.id']] = _redfishobj.get(controller['@odata.id']).obj
        sys.stdout.write("Logical Drive URIs for Smart Storage Array Controller \'%s\' : \n" \
                                        % smartarraycontrollers[controller['@odata.id']].get('Id'))
        logicaldrives_uri = smartarraycontrollers[controller['@odata.id']].Links\
                                                                    ['LogicalDrives']['@odata.id']
        logicaldrives_resp = _redfishobj.get(logicaldrives_uri)
        smartarraycontrollers[controller['@odata.id']]['LogicalDrives'] = logicaldrives_resp.dict\
                                                                                        ['Members']
        if not logicaldrives_resp.dict['Members']:
            sys.stderr.write("\tLogical drives are not available for this controller.\n")
        for lds in logicaldrives_resp.dict['Members']:
            sys.stdout.write("\t An associated logical drive: %s\n" % logicaldrives_resp.dict['Name'])
            drive_data = _redfishobj.get(lds['@odata.id']).dict
            print(json.dumps(drive_data, indent=4, sort_keys=True))

def get_SmartArray_LogicalDrives_gen9(_redfishobj):

    smartstorage_response = []
    smartarraycontrollers = dict()

    smartstorage_uri = "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
    print (smartstorage_uri)
    smartstorage_response = _redfishobj.get(smartstorage_uri).obj['Members']

    for controller in smartstorage_response:
        smartarraycontrollers[controller['@odata.id']] = _redfishobj.get(controller['@odata.id']).obj
        sys.stdout.write("Logical Drive URIs for Smart Storage Array Controller \'%s\' : \n" \
                                        % smartarraycontrollers[controller['@odata.id']].get('Id'))
        logicaldrives_uri = smartarraycontrollers[controller['@odata.id']].Links\
                                                                    ['LogicalDrives']['@odata.id']
        print (logicaldrives_uri)
        logicaldrives_resp = _redfishobj.get(logicaldrives_uri)
        if logicaldrives_resp.dict['Members@odata.count'] == 0:
            sys.stderr.write("\tLogical drives are not available for this controller.\n")
        else:
            for lds in logicaldrives_resp.dict['Members']:
                sys.stdout.write("\t An associated logical drive: %s\n" % logicaldrives_resp.dict['Name'])
                drive_data = _redfishobj.get(lds['@odata.id']).dict
                print(json.dumps(drive_data, indent=4, sort_keys=True))

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

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
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
        get_SmartArray_LogicalDrives(redfish_obj)
    else:
        get_SmartArray_LogicalDrives_gen9(redfish_obj)
    redfish_obj.logout()
