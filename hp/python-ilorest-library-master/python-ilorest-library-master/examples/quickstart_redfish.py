###
# Copyright 2020 Hewlett Packard Enterprise, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

# -*- coding: utf-8 -*-
"""A quickstart example for RedfishClient"""

import sys
import redfish

# When running on the server locally use the following commented values
# HOST = "blobstore://."
# LOGIN_ACCOUNT = "None"
# LOGIN_PASSWORD = "None"

# When running remotely connect using the iLO address, iLO account name,
# and password to send https requests
SYSTEM_URL = "https://10.0.0.100"
LOGIN_ACCOUNT = "admin"
LOGIN_PASSWORD = "password"

## Create a REDFISH object
REDFISH_OBJ = redfish.RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT,\
                                    password=LOGIN_PASSWORD)

# Login into the server and create a session
REDFISH_OBJ.login()

# Do a GET on a given path
RESPONSE = REDFISH_OBJ.get("/redfish/v1/systems/1")

# Print out the response
sys.stdout.write("%s\n" % RESPONSE)

# Logout of the current session
REDFISH_OBJ.logout()
