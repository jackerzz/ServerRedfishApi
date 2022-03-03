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
import argparse
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
global DISABLE_RESOURCE_DIR
from ilorest_util import get_resource_directory
from ilorest_util import get_gen

def reset_server(_redfishobj):
    
    managers_members_response = None
    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        managers_uri = _redfishobj.root.obj['Systems']['@odata.id']
        managers_response = _redfishobj.get(managers_uri)
        managers_members_uri = next(iter(managers_response.obj['Members']))['@odata.id']
        managers_members_response = _redfishobj.get(managers_members_uri)
    else:
        #Use Resource directory to find the relevant URI
        for instance in resource_instances:
            if "ComputerSystem." in instance['@odata.type']:
                managers_members_uri = instance['@odata.id']
                managers_members_response = _redfishobj.get(managers_members_uri)
                
    if managers_members_response:
        path = managers_members_response.obj["Actions"]["#ComputerSystem.Reset"]["target"]
        body = dict()
        body["Action"] = "ComputerSystem.Reset"
        body["ResetType"] = "ForceRestart"
        resp = _redfishobj.post(path, body)

    #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
    #error message to see what went wrong
    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended Message "\
                             "Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
    else:
        print("Success!\n")
        print(json.dumps(resp.dict, indent=4, sort_keys=True))
        
def reset_server_gen9(_redfishobj):
    
    managers_uri = "/redfish/v1/Systems/1/"
    managers_response = _redfishobj.get(managers_uri)
    system_path = managers_response.obj["Actions"]["#ComputerSystem.Reset"]["target"]
    print(system_path)
    body = dict()
    body["Action"] = "Reset"
    body["ResetType"] = "ForceRestart"

    resp = _redfishobj.post(system_path, body)
    #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended info
    #error message to see what went wrong
    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended Message "\
                             "Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
    else:
        print("Success!\n")
        print(json.dumps(resp.dict, indent=4, sort_keys=True))

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
    DISABLE_RESOURCE_DIR = True

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
        reset_server(redfish_obj)
    else:
        reset_server_gen9(redfish_obj)
    redfish_obj.logout()
