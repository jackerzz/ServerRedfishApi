#
# RemoveControllerKeyREDFISH. Python script using Redfish API with OEM extension to remove the storage controller key (remove encryption)
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 4.0
#
# Copyright (c) 2019, Dell, Inc.
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

parser=argparse.ArgumentParser(description="Python script using Redfish API with OEM extenstion to remove the storage controller key (remove encryption)")
parser.add_argument('-ip',help='iDRAC IP address', required=True)
parser.add_argument('-u', help='iDRAC username', required=True)
parser.add_argument('-p', help='iDRAC password', required=True)
parser.add_argument('script_examples',action="store_true",help='RemoveControllerKeyREDFISH.py -ip 192.168.0.120 -u root -p calvin -c y, this example will return storage controller FQDDs detected. RemoveControllerKeyREDFISH.py -ip 192.168.0.120 -u root -p calvin -r RAID.Slot.6-1, this example is removing the controller key for RAID.Slot.6-1 controller')
parser.add_argument('-c', help='Get server storage controller FQDDs, pass in \"y\"', required=False)
parser.add_argument('-g', help='Get current controller encryption mode settings, pass in controller FQDD, Example \"RAID.Slot.6-1\"', required=False)
parser.add_argument('-v', help='Get current server storage controller virtual disk(s) and virtual disk type, pass in storage controller FQDD, Example "\RAID.Integrated.1-1\"', required=False)
parser.add_argument('-vv', help='Get current server storage controller virtual disk detailed information, pass in storage controller FQDD, Example "\RAID.Integrated.1-1\"', required=False)
parser.add_argument('-cl', help='Check for current locked virtual disks, pass in storage controller FQDD, Example "\RAID.Integrated.1-1\"', required=False)
parser.add_argument('-r', help='Remove the controller key, pass in the controller FQDD, Example \"RAID.Slot.6-1\"', required=False)


args=vars(parser.parse_args())

idrac_ip=args["ip"]
idrac_username=args["u"]
idrac_password=args["p"]


def check_supported_idrac_version():
    response = requests.get('https://%s/redfish/v1/Dell/Systems/System.Embedded.1/DellRaidService' % idrac_ip,verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    if response.status_code != 200:
        print("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
        sys.exit()
    else:
        pass


def get_storage_controllers():
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage' % idrac_ip,verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    print("\n- Server controller(s) detected -\n")
    controller_list=[]
    for i in data['Members']:
        controller_list.append(i['@odata.id'].split("/")[-1])
        print(i['@odata.id'].split("/")[-1])
    

def get_virtual_disks():
    test_valid_controller_FQDD_string(args["v"])
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["v"]),verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    vd_list=[]
    if data['Members'] == []:
        print("\n- WARNING, no volume(s) detected for %s" % args["v"])
        sys.exit()
    else:
        for i in data['Members']:
            vd_list.append(i['@odata.id'].split("/")[-1])
    print("\n- Volume(s) detected for %s controller -" % args["v"])
    print("\n")
    for ii in vd_list:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/Volumes/%s' % (idrac_ip, ii),verify=False,auth=(idrac_username, idrac_password))
        data = response.json()
        for i in data.items():
            if i[0] == "VolumeType":
                print("%s, Volume type: %s" % (ii, i[1]))
    sys.exit()


def get_virtual_disk_details():
    test_valid_controller_FQDD_string(args["vv"])
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["vv"]),verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    vd_list=[]
    if data['Members'] == []:
        print("\n- WARNING, no volume(s) detected for %s" % args["vv"])
        sys.exit()
    else:
        print("\n- Volume(s) detected for %s controller -\n" % args["vv"])
        for i in data['Members']:
            vd_list.append(i['@odata.id'].split("/")[-1])
            print(i['@odata.id'].split("/")[-1])
    for ii in vd_list:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/Volumes/%s' % (idrac_ip, ii),verify=False,auth=(idrac_username, idrac_password))
        data = response.json()
        print("\n - Detailed Volume information for %s -\n" % ii)
        for i in data.items():
            print("%s: %s" % (i[0],i[1]))
                
    sys.exit()

def get_controller_encryption_setting():
    test_valid_controller_FQDD_string(args["g"])
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["g"]),verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    try:
        print("\n- Encryption Mode Settings for controller %s -\n" % args["g"])
        print("EncryptionMode: %s" % data['Oem']['Dell']['DellController']['EncryptionMode'])
        print("EncryptionCapability: %s" % data['Oem']['Dell']['DellController']['EncryptionCapability'])
        print("SecurityStatus: %s" % data['Oem']['Dell']['DellController']['SecurityStatus'])
    except:
        print("- FAIL, invalid controller FQDD string passed in")
        
def check_lock_VDs():
    test_valid_controller_FQDD_string(args["cl"])
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s/Volumes' % (idrac_ip, args["cl"]),verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    vd_list=[]
    if data['Members'] == []:
        print("\n- WARNING, no volume(s) detected for %s" % args["cl"])
        sys.exit()
    else:
        for i in data['Members']:
            vd_list.append(i['@odata.id'][54:])
    print("\n- Volume(s) detected for %s controller -\n" % args["cl"])
    for ii in vd_list:
        response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/Volumes/%s' % (idrac_ip, ii),verify=False,auth=(idrac_username, idrac_password))
        data = response.json()
        for i in data.items():
            if i[0] == "Encrypted":
                print("%s, Encrypted(Lock) Status: %s" % (ii, i[1]))
    sys.exit()

def remove_controller_key():
    global job_id
    test_valid_controller_FQDD_string(args["r"])
    method = "RemoveControllerKey"
    url = 'https://%s/redfish/v1/Dell/Systems/System.Embedded.1/DellRaidService/Actions/DellRaidService.RemoveControllerKey' % (idrac_ip)
    headers = {'content-type': 'application/json'}
    payload={"TargetFQDD": args["r"]}
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 202:
        print("\n-PASS: POST command passed to remove storage controller %s key , status code %s returned" % (args["r"],response.status_code))
        try:
            job_id = response.headers['Location'].split("/")[-1]
        except:
            print("- FAIL, unable to locate job ID in JSON headers output")
            sys.exit()
        print("- Job ID %s successfully created for storage method \"%s\"" % (job_id, method)) 
    else:
        print("\n-FAIL, POST command failed to remove storage controller %s key, status code is %s" % (args["r"], response.status_code))
        data = response.json()
        print("\n-POST command failure results:\n %s" % data)
        sys.exit()
        
def loop_job_status():
    start_time=datetime.now()
    while True:
        req = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/%s' % (idrac_ip, job_id), auth=(idrac_username, idrac_password), verify=False)
        current_time=(datetime.now()-start_time)
        statusCode = req.status_code
        if statusCode == 200:
            pass
        else:
            print("\n- FAIL, Command failed to check job status, return code is %s" % statusCode)
            print("Extended Info Message: {0}".format(req.json()))
            sys.exit()
        data = req.json()
        if str(current_time)[0:7] >= "2:00:00":
            print("\n- FAIL: Timeout of 2 hours has been hit, script stopped\n")
            sys.exit()
        elif "Fail" in data['Message'] or "fail" in data['Message'] or data['JobState'] == "Failed":
            print("- FAIL: job ID %s failed, failed message is: %s" % (job_id, data['Message']))
            sys.exit()
        elif data['JobState'] == "Completed":
            print("\n--- PASS, Final Detailed Job Status Results ---\n")
            for i in data.items():
                if "odata" in i[0] or "MessageArgs" in i[0] or "TargetSettingsURI" in i[0]:
                    pass
                else:
                    print("%s: %s" % (i[0],i[1]))
            break
        else:
            print("- INFO, job status not completed, current status: \"%s\"" % (data['Message']))
            time.sleep(3)

def get_controller_encryption_setting_final_check():
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, args["r"]),verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    if data['Oem']['Dell']['DellController']['EncryptionMode'] == "None":
        print("\n- PASS, encryption NOT enabled for storage controller %s" % args["r"])
    else:
        print("- FAIL, encryption mode still enabled, current setting is %s" % data['Oem']['Dell']['DellController']['EncryptionMode'])
        sys.exit()

def test_valid_controller_FQDD_string(x):
    response = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1/Storage/%s' % (idrac_ip, x),verify=False,auth=(idrac_username, idrac_password))
    if response.status_code != 200:
        print("\n- FAIL, either controller FQDD does not exist or typo in FQDD string name (FQDD controller string value is case sensitive)")
        sys.exit()
    else:
        pass
    

if __name__ == "__main__":
    check_supported_idrac_version()
    if args["c"]:
        get_storage_controllers()
    elif args["v"]:
        get_virtual_disks()
    elif args["vv"]:
        get_virtual_disk_details()
    elif args["cl"]:
        check_lock_VDs()
    elif args["r"]:
        remove_controller_key()
        loop_job_status()
        get_controller_encryption_setting_final_check()
    elif args["g"]:
        get_controller_encryption_setting()
    else:
        print("\n- FAIL, either missing parameter(s) or incorrect parameter(s) passed in. If needed, execute script with -h for script help")
    
    
        
            
        
        
