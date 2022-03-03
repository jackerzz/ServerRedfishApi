#
# ExportHWInventoryREDFISH. Python script using Redfish API with OEM extension to export server hardware(HW) inventory to either local directory or network share
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


import requests, json, sys, re, time, warnings, argparse, os

from datetime import datetime

warnings.filterwarnings("ignore")

parser=argparse.ArgumentParser(description="Python script using Redfish API with OEM extension to export server hardware(HW) inventory to either local directory or supported network share")
parser.add_argument('-ip',help='iDRAC IP address', required=True)
parser.add_argument('-u', help='iDRAC username', required=True)
parser.add_argument('-p', help='iDRAC password', required=True)
parser.add_argument('script_examples',action="store_true",help='ExportHWInventoryREDFISH.py -ip 192.168.0.120 -u root -p calvin --ipaddress 192.168.0.130 --sharetype CIFS --sharename cifs_share_vm --username administrator --password pass --filename export_hw_inv.xml, this example will export the server hardware inventory to a CIFS share. ExportHWInventoryREDFISH.py -ip 192.168.0.120 -u root -p calvin --sharetype local, this example will export the HW configuration locally to an XML file.')
parser.add_argument('-s', help='Get supported network share types, pass in \"y\"', required=False)
parser.add_argument('--ipaddress', help='Pass in the IP address of the network share', required=False)
parser.add_argument('--sharetype', help='Pass in the share type of the network share to export or pass in "Local" to perform local export. For supported network share types, execute -s argument. NOTE: When passing in Local for share type, you don\'t need to pass in any other arguments. This exported HW inventory file will be in XML format.', required=False)
parser.add_argument('--sharename', help='Pass in the network share share name', required=False)
parser.add_argument('--username', help='Pass in the CIFS username', required=False)
parser.add_argument('--password', help='Pass in the CIFS username pasword', required=False)
parser.add_argument('--workgroup', help='Pass in the workgroup of your CIFS network share. This argument is optional', required=False)
parser.add_argument('--filename', help='Pass in unique file name string for the export Hw inventory file', required=False)
parser.add_argument('--ignorecertwarning', help='Supported values are Off and On. This argument is only required if using HTTPS for share type', required=False)



args=vars(parser.parse_args())

idrac_ip=args["ip"]
idrac_username=args["u"]
idrac_password=args["p"]


def check_supported_idrac_version():
    response = requests.get('https://%s/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLCService' % idrac_ip,verify=False,auth=(idrac_username, idrac_password))
    if response.__dict__['reason'] == "Unauthorized":
        print("\n- FAIL, unauthorized to execute Redfish command. Check to make sure you are passing in correct iDRAC username/password and the IDRAC user has the correct privileges")
        sys.exit()
    else:
        pass
    data = response.json()
    supported = "no"
    for i in data['Actions'].keys():
        if "ExportHWInventory" in i:
            supported = "yes"
        else:
            pass
    if supported == "no":
        print("\n- WARNING, iDRAC version installed does not support this feature using Redfish API")
        sys.exit()
    else:
        pass


def get_supported_network_share_types():
    response = requests.get('https://%s/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLCService' % idrac_ip,verify=False,auth=(idrac_username, idrac_password))
    data = response.json()
    print("\n- Supported network share types for ExportHWInventory Action -\n")
    for i in data['Actions'].items():
        if i[0] == "#DellLCService.ExportHWInventory":
            for ii in i[1]['ShareType@Redfish.AllowableValues']:
                print(ii)
        




def export_hw_inventory():
    global job_id
    url = 'https://%s/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLCService/Actions/DellLCService.ExportHWInventory' % (idrac_ip)
    method = "ExportHWInventory"
    headers = {'content-type': 'application/json'}
    payload={}
        
    headers = {'content-type': 'application/json'}
    payload={}
    if args["ipaddress"]:
        payload["IPAddress"] = args["ipaddress"]
    if args["sharetype"]:
        if args["sharetype"] == "local" or args["sharetype"] == "Local":
            payload["ShareType"] = args["sharetype"].title()
        else:
            payload["ShareType"] = args["sharetype"].upper()
    if args["sharename"]:
        payload["ShareName"] = args["sharename"]
    if args["filename"]:
            payload["FileName"] = args["filename"]
    if args["username"]:
        payload["UserName"] = args["username"]
    if args["password"]:
        payload["Password"] = args["password"]
    if args["workgroup"]:
        payload["Workgroup"] = args["workgroup"]
    if args["ignorecertwarning"]:
        payload["IgnoreCertWarning"] = args["ignorecertwarning"]
    print("\n- WARNING, arguments and values for %s method\n" % method)
    for i in payload.items():
        if i[0] == "Password":
            print("Password: ********")
        else:
            print("%s: %s" % (i[0],i[1]))
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False,auth=(idrac_username,idrac_password))
    data = response.json()
    if response.status_code == 202:
        print("\n- PASS: POST command passed for %s method, status code 202 returned" % method)
    else:
        print("\n- FAIL, POST command failed for %s method, status code is %s" % (method, response.status_code))
        data = response.json()
        print("\n- POST command failure results:\n %s" % data)
        sys.exit()
    if args["sharetype"] == "local" or args["sharetype"] == "Local":
        get_service_tag = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % (idrac_ip),verify=False,auth=(idrac_username, idrac_password))
        data_get_service_tag = get_service_tag.json()
        chassis_service_tag = data_get_service_tag['Oem']['Dell']['DellSystem']['NodeID']
        print("- WARNING, Redfish export HW inventory URI: \"%s\"\n" % response.headers['Location'])
        response = requests.get('https://%s%s' % (idrac_ip, response.headers['Location']),verify=False,auth=(idrac_username, idrac_password))
        get_datetime_info = datetime.now()
        export_filename = "%s-%s-%s_%s%s%s_export_HW_inventory_%s.xml"% (get_datetime_info.year, get_datetime_info.month, get_datetime_info.day, get_datetime_info.hour, get_datetime_info.minute, get_datetime_info.second, chassis_service_tag)
        filename_open = open(export_filename,"a")
        dict_response = response.__dict__['_content']
        string_convert=str(dict_response)
        string_convert=string_convert.lstrip("'b")
        string_convert=string_convert.rstrip("'")
        string_convert=string_convert.split("\\n")
        for i in string_convert:
            filename_open.writelines(i)
            filename_open.writelines("\n")
        filename_open.close()
        print("- Exported HW inventory captured to file \"%s\%s\"" % (os.getcwd(), export_filename))
        sys.exit()
    else:
        try:
            job_id = response.headers['Location'].split("/")[-1]
        except:
            print("- FAIL, unable to find job ID in headers POST response, headers output is:\n%s" % response.headers)
            sys.exit()
        print("- PASS, job ID %s successfuly created for %s method\n" % (job_id, method))
    


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
        if str(current_time)[0:7] >= "0:05:00":
            print("\n- FAIL: Timeout of 5 minutes has been hit, script stopped\n")
            sys.exit()
        elif "Fail" in data[u'Message'] or "fail" in data[u'Message'] or data[u'JobState'] == "Failed" or "Unable" in data[u'Message']:
            print("- FAIL: job ID %s failed, failed message is: %s" % (job_id, data[u'Message']))
            sys.exit()
        elif data[u'JobState'] == "Completed":
            if data[u'Message'] == "Hardware Inventory Export was successful":
                print("\n--- PASS, Final Detailed Job Status Results ---\n")
            else:
                print("\n--- FAIL, Final Detailed Job Status Results ---\n")
            for i in data.items():
                if "odata" in i[0] or "MessageArgs" in i[0] or "TargetSettingsURI" in i[0]:
                    pass
                else:
                    print("%s: %s" % (i[0],i[1]))
            break
        else:
            print("- WARNING, job state not marked completed, current job status is running, polling again")
            

    

if __name__ == "__main__":
    check_supported_idrac_version()
    if args["s"]:
        get_supported_network_share_types()
    else:
        export_hw_inventory()
        loop_job_status()
    
    
        
            
        
        
