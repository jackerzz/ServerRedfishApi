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
from urllib3.util import parse_url
from redfish import LegacyRestClient
from get_resource_directory import get_resource_directory

def sessions(restobj, login_account, login_password):
    new_session = {"UserName": login_account, "Password": login_password}
    response = restobj.post("/rest/v1/Sessions", new_session)
    sys.stdout.write("%s" % response)

    if response.status == 201:
        session_uri = response.getheader("location")
        session_uri = parse_url(session_uri)
        sys.stdout.write("\tSession " + session_uri.path + " created\n")

        x_auth_token = response.getheader("x-auth-token")
        sys.stdout.write("\tSession key " + x_auth_token + " created\n")

        # Delete the created session
        sessresp = restobj.delete(session_uri.path)
        sys.stdout.write("%s" % response)
    else:
        sys.stderr.write("ERROR: failed to create a session.\n")

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
    sys.stdout.write("\nEXAMPLE 14: Create/Use/Delete a user session\n")
    sessions(REST_OBJ, "admin", "admin123")
