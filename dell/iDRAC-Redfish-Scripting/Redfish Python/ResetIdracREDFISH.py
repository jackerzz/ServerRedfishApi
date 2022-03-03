#
# ResetIdracREDFISH. Python script using Redfish API to reset iDRAC.
#
# NOTE: Once the script is complete, iDRAC will reset to complete the process and you will lose network connection. iDRAC should be back up within a few minutes.
# 
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 3.0
#
# Copyright (c) 2017, Dell, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#

import requests, json, sys, re, time, warnings, argparse

from datetime import datetime

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description='Python script using Redfish API to reset the iDRAC')
parser.add_argument('-ip', help='iDRAC IP Address', required=True)
parser.add_argument('-u', help='iDRAC username', required=True)
parser.add_argument('-p', help='iDRAC password', required=True)
parser.add_argument('script_examples',action="store_true",help='ResetIdracREDFISH.py -ip 192.168.0.120 -u root -p calvin, this example will reset the iDRAC and be back online after a few minutes, same behavior as \"racadm racreset\" command')

args = vars(parser.parse_args())

idrac_ip=args["ip"]
idrac_username=args["u"]
idrac_password=args["p"]

### Function to reset iDRAC.

def reset_idrac():
    
    url = "https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset/" % idrac_ip
    payload={"ResetType":"GracefulRestart"}
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(payload), headers=headers,verify=False, auth=(idrac_username, idrac_password))
    if response.status_code == 204:
        print("\n- PASS, status code %s returned for POST command to reset iDRAC\n" % response.status_code)
    else:
        data=response.json()
        print("\n- FAIL, status code %s returned, detailed error is: \n%s" % (response.status_code, data))
        sys.exit()
    time.sleep(15)
    print("- WARNING, iDRAC will now reset and be back online within a few minutes.")
    
### Run code

if __name__ == "__main__":
    reset_idrac()

