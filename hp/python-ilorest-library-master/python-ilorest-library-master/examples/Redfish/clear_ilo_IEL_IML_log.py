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
An example of clearing IEL or IML Logs for HPE iLO systems
"""

import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

from get_resource_directory import get_resource_directory

def clear_ilo_event_log(_redfishobj, clear_IML_IEL):

    clear_log_services_uri = []

    resource_instances = get_resource_directory(_redfishobj)
    if DISABLE_RESOURCE_DIR or not resource_instances:
        #if we do not have a resource directory or want to force it's non use to find the
        #relevant URI
        systems_uri = _redfishobj.root.obj['Systems']['@odata.id']
        systems_response = _redfishobj.get(systems_uri)
        systems_members_uri = next(iter(systems_response.obj['Members']))['@odata.id']
        systems_members_response = _redfishobj.get(systems_members_uri)
        log_services_uri = systems_members_response.obj['LogServices']['@odata.id']
        log_services_response = _redfishobj.get(log_services_uri)
        log_services_uris = log_services_response.obj['Members']
        for log_services_uri in log_services_uris:
            log_services_response = _redfishobj.get(log_services_uri['@odata.id'])
            clear_log_services_uri.append(log_services_response.obj['Actions']\
                                                                ['#LogService.ClearLog']['target'])
    else:
        for instance in resource_instances:
            #Use Resource directory to find the relevant URI
            if '#LogService.' in instance['@odata.type']:
                log_service_uri = instance['@odata.id']
                clear_log_services_uri.append(_redfishobj.get(log_service_uri).dict['Actions']\
                                                                ['#LogService.ClearLog']['target'])

    if clear_log_services_uri:
        body = {"Action": "LogService.ClearLog"}
        for path in clear_log_services_uri:
            if ("IEL" in clear_IML_IEL and "IEL" in path) or ("IML" in clear_IML_IEL and \
                                                                                    "IML" in path):
                if "IEL" in path:
                    sys.stdout.write("Clearing IEL log.\n")
                else:
                    sys.stdout.write("Clearing IML log.\n")
                resp = _redfishobj.post(path, body)
            else:
                continue
            #If iLO responds with soemthing outside of 200 or 201 then lets check the iLO extended
            #info error message to see what went wrong
            if resp.status == 400:
                try:
                    print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                                    sort_keys=True))
                except Exception as excp:
                    sys.stderr.write("A response error occurred, unable to access iLO "\
                                     "Extended Message Info...\n")
            elif resp.status != 200:
                sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
            else:
                print("Success!\n")
                print(json.dumps(resp.dict, indent=4, sort_keys=True))

if __name__ == "__main__":
    # When running on the server locally use the following commented values
    #SYSTEM_URL = None
    #LOGIN_ACCOUNT = None
    #LOGIN_PASSWORD = None

    # When running remotely connect using the secured (https://) address,
    # account name, and password to send https requests
    # SYSTEM_URL acceptable examples:
    # "https://10.0.0.100"
    # "https://ilo.hostname"
    SYSTEM_URL = "https://10.0.0.100"
    LOGIN_ACCOUNT = "admin"
    LOGIN_PASSWORD = "password"

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = False
    CLEAR_IML_IEL = "IML" # provide either the string IML or IEL

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    clear_ilo_event_log(REDFISHOBJ, CLEAR_IML_IEL)
    REDFISHOBJ.logout()
