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
An example of obtaining system schema data
"""

import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError

def get_schema(_redfishobj):
    schema_members_uris = []
    schema_members_expanded = {}

    schema_uri = _redfishobj.root.obj['JsonSchemas']['@odata.id']
    schema_response = _redfishobj.get(schema_uri)
    schema_members_uris = schema_response.obj['Members']
    for member in schema_members_uris:
        data = _redfishobj.get(member['@odata.id']).dict
        instance_id = data['Location'].index(next(iter(data['Location'])))
        schema_uri = data['Location'][instance_id]['Uri']
        schema = _redfishobj.get(schema_uri).dict
        #I am just replacing the URI link for the sub-schema with the actual schema. You will
        #see EVERYTHING
        _tmp = {schema_uri + ' ->': schema}
        data['Location'][instance_id]['Uri'] = _tmp
        schema_members_expanded[member['@odata.id']] = data

    print(json.dumps(schema_members_expanded, indent=4, sort_keys=True))

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

    try:
        # Create a Redfish client object
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT, \
                                                                            password=LOGIN_PASSWORD)
        # Login with the Redfish client
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    get_schema(REDFISHOBJ)
    REDFISHOBJ.logout()
