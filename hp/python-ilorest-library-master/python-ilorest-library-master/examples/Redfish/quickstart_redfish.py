# -*- coding: utf-8 -*-
import sys
import redfish

# When running on the server locally use the following commented values
# iLO_host = "blobstore://."
# LOGIN_ACCOUNT = "None"
# LOGIN_PASSWORD = "None"

# When running remotely connect using the iLO address, iLO account name, 
# and password to send https requests
iLO_host = "https://10.0.0.100"
login_account = "admin"
login_password = "password"

## Create a REDFISH object
REDFISH_OBJ = redfish.RedfishClient(base_url=iLO_host,username=login_account, \
                          password=login_password)

# Login into the server and create a session
REDFISH_OBJ.login()

# Do a GET on a given path
response = REDFISH_OBJ.get("/redfish/v1/systems/1")

# Print out the response
sys.stdout.write("%s\n" % response)

# Logout of the current session
REDFISH_OBJ.logout()