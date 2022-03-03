#
# ExportServerConfigurationLocalREDFISH. Python script using Redfish API with OEM extension to export the system configuration locally. By default, POST command print all attributes to the screen. This script will also capture these attributes into a file.
#
# 
#
# _author_ = Texas Roemer <Texas_Roemer@Dell.com>
# _version_ = 7.0
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

parser=argparse.ArgumentParser(description="Python script using Redfish API with OEM extension to export the host server configuration profile locally in either XML or JSON format.")
parser.add_argument('-ip',help='iDRAC IP address', required=True)
parser.add_argument('-u', help='iDRAC username', required=True)
parser.add_argument('-p', help='iDRAC password', required=True)
parser.add_argument('script_examples',action="store_true",help='ExportSystemConfigurationLocalREDFISH.py -ip 192.168.0.120 -u root -p calvin -t ALL, this example will export all components locally in XML format. ExportSystemConfigurationLocalREDFISH.py -ip 192.168.0.120 -u root -p calvin -t BIOS -f JSON, this example will export only BIOS attributes in JSON format.')
parser.add_argument('-t', help='Pass in Target value to get component attributes. You can pass in \"ALL" to get all component attributes or pass in a specific component to get only those attributes. Supported values are: ALL, System, BIOS, IDRAC, NIC, FC, LifecycleController, RAID, EventFilters.', required=True)
parser.add_argument('-e', help='Pass in ExportUse value. Supported values are Default, Clone and Replace. If you don\'t use this parameter, default setting is Default or Normal export.', required=False)
parser.add_argument('-i', help='Pass in IncludeInExport value. Supported values are 1 for \"Default\", 2 for \"IncludeReadOnly\", 3 for \"IncludePasswordHashValues\" or 4 for \"IncludeReadOnly,IncludePasswordHashValues\". If you don\'t use this parameter, default setting is Default for IncludeInExport.', required=False)
parser.add_argument('-f', help='Pass in Export format type, either \"XML\" or \"JSON\". Note, If you don\'t pass in this argument, default setting is XML', required=False)
parser.add_argument('-d', help='Pass in directory path where you want the SCP file saved to. If you don\'t pass in this argument, SCP file will be saved to the directory you are executing the script from.', required=False)
args=vars(parser.parse_args())

idrac_ip=args["ip"]
idrac_username=args["u"]
idrac_password=args["p"]


if args["f"] == None:
    args["f"] = "XML"
else:
    pass

url = 'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ExportSystemConfiguration' % idrac_ip
payload = {"ExportFormat":args["f"].upper(),"ShareParameters":{"Target":args["t"]}}
if args["e"]:
    payload["ExportUse"] = args["e"]
if args["i"]:
    if args["i"] == "1":
        payload["IncludeInExport"] = "Default"
    if args["i"] == "2":
        payload["IncludeInExport"] = "IncludeReadOnly"
    if args["i"] == "3":
        payload["IncludeInExport"] = "IncludePasswordHashValues"
    if args["i"] == "4":
        payload["IncludeInExport"] = "IncludeReadOnly,IncludePasswordHashValues"

headers = {'content-type': 'application/json'}
response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False, auth=(idrac_username,idrac_password))

if response.status_code != 202:
    print("- FAIL, status code not 202, code is: %s" % response.status_code)
    print("- Error details: %s" % response.__dict__)
    sys.exit()
else:
    success_job_status = "\n- Job ID \"%s\" successfully created for ExportSystemConfiguration method\n" 

response_output=response.__dict__
job_id=response_output["headers"]["Location"]

try:
    job_id=re.search("JID_.+",job_id).group()
except:
    print("\n- FAIL: detailed error message: {0}".format(response.__dict__['_content']))
    sys.exit()

print(success_job_status % job_id)
start_time=datetime.now()

while True:
    current_time=(datetime.now()-start_time)
    req = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (idrac_ip, job_id), auth=(idrac_username, idrac_password), verify=False)
    dict_output = req.__dict__
    if args["f"] == "XML":
        if "<SystemConfiguration Model" in str(dict_output):
            print("\n- Export locally job ID %s successfully completed. Attributes exported:\n" % job_id)
            regex_search = re.search("<SystemConfiguration.+</SystemConfiguration>",str(dict_output)).group()
            try:
                security_string = re.search('<Attribute Name="GUI.1#SecurityPolicyMessage">.+?>', regex_search).group()
            except:
                pass
        
            #Below code is needed to parse the string to set up in pretty XML format
            replace_variable = regex_search.replace("\\n"," ")
            replace_variable = replace_variable.replace("<!--  ","<!--")
            replace_variable = replace_variable.replace(" -->","-->")
            del_attribute = '<Attribute Name="SerialRedirection.1#QuitKey">^\\\\</Attribute>'
            try:
                replace_variable = replace_variable.replace(del_attribute,"")
            except:
                pass
            try:
                replace_variable = replace_variable.replace(security_string,"")
            except:
                pass
            create_list = replace_variable.split("> ")
            export_xml=[]
            for i in create_list:
                create_string = i+">"
                export_xml.append(create_string)
            export_xml[-1]="</SystemConfiguration>"
            get_date_info = datetime.now()
            if args["d"]:
                filename="%s\%s-%s-%s_%s%s%s_export.xml"% (args["d"],get_date_info.year,get_date_info.month,get_date_info.day,get_date_info.hour,get_date_info.minute,get_date_info.second)
            else:
                filename="%s-%s-%s_%s%s%s_export.xml"% (get_date_info.year,get_date_info.month,get_date_info.day,get_date_info.hour,get_date_info.minute,get_date_info.second)
            open_file = open(filename,"w")
            for i in export_xml:
                open_file.writelines("%s \n" % i)
            open_file.close()
            for i in export_xml:
                print(i)

            print("\n")
            req = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/%s' % (idrac_ip, job_id), auth=(idrac_username, idrac_password), verify=False)
            
            data = req.json()
            print("\n- PASS, final detailed job status results for job ID %s -\n" % job_id)
            for i in data.items():
                print("%s: %s" % (i[0],i[1]))
            print("\n- Exported attributes also saved in file: %s" % filename)
            sys.exit()
        else:
            pass
    elif args["f"] == "JSON":
        if "SystemConfiguration" in str(dict_output):
            data = req.json()
            json_format = json.dumps(data)
            get_date_info=datetime.now()
            if args["d"]:
                filename="%s\%s-%s-%s_%s%s%s_export.json"% (args["d"],get_date_info.year,get_date_info.month,get_date_info.day,get_date_info.hour,get_date_info.minute,get_date_info.second)
            else:
                filename="%s-%s-%s_%s%s%s_export.json"% (get_date_info.year,get_date_info.month,get_date_info.day,get_date_info.hour,get_date_info.minute,get_date_info.second)
            open_file = open(filename,"w")
            open_file.write(json.dumps(json.loads(json_format), indent=4))
            open_file.close()
            req = requests.get('https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/%s' % (idrac_ip, job_id), auth=(idrac_username, idrac_password), verify=False)
            data = req.json()
            print("\n- PASS, final detailed job status results for job ID %s -\n" % job_id)
            for i in data.items():
                print("%s: %s" % (i[0],i[1]))
            print("\n- Exported attributes saved to file: %s" % filename)
            sys.exit()
        else:
            pass
    
        
    statusCode = req.status_code
    data = req.json()
    try:
        message_string=data[u"Messages"]
    except:
        print(statusCode)
        print(data)
        sys.exit()
    current_time=(datetime.now()-start_time)

    if statusCode == 202 or statusCode == 200:
        time.sleep(1)
        pass
    else:
        print("Execute job ID command failed, error code is: %s" % statusCode)
        sys.exit()
    if str(current_time)[0:7] >= "0:10:00":
        print("\n-FAIL, Timeout of 10 minutes has been reached before marking the job completed.")
        sys.exit()

    else:
        try:
            print("- INFO, JobStatus not completed, current status: \"%s\", percent complete: \"%s\"" % (data['Oem']['Dell']['Message'],data['Oem']['Dell']['PercentComplete']))
            time.sleep(1)
        except:
            print("- INFO, unable to print job status message, trying again")
            time.sleep(1)
        continue


       
