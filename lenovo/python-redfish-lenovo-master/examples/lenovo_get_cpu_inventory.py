###
#
# Lenovo Redfish examples - Get the CPU information
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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
###



import sys
import json
import redfish
import traceback
import lenovo_utils as utils


def lenovo_get_cpu_inventory(ip, login_account, login_password, system_id, member_id):
    """Get cpu inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params member_id: Cpu member id
    :type member_id: None or int
    :returns: returns cpu inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    cpu_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result

    for i in range(len(system)):
        # Get Processors url
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            processors_url = response_system_url.dict['Processors']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get the Processors collection
        response_processors_url = REDFISH_OBJ.get(processors_url, None)
        if response_processors_url.status == 200:
            # Get Members url
            members_count = response_processors_url.dict['Members@odata.count']
        else:
            result = {'ret': False, 'msg': "response_processors_url Error code %s" % response_processors_url.status}
            REDFISH_OBJ.logout()
            return result

        # check member_id validity
        if member_id != None:
            if member_id <= 0 or member_id > members_count:
                result = {'ret': False, 'msg': "Specified member id is not valid. The id should be within 1~%s" % (members_count)}
                REDFISH_OBJ.logout()
                return result

        # Get each processor info
        for i in range(members_count):
            if member_id != None  and i != (member_id-1):
                continue
            cpu = {}
            # Get members url resource
            members_url = response_processors_url.dict['Members'][i]['@odata.id']
            response_members_url = REDFISH_OBJ.get(members_url, None)
            if response_members_url.status == 200:
                for property in ['Id', 'Name', 'TotalThreads', 'InstructionSet', 'Status', 'ProcessorType', 
                    'TotalCores', 'Manufacturer', 'MaxSpeedMHz', 'Model', 'Socket']:
                    if property in response_members_url.dict:
                        cpu[property] = response_members_url.dict[property]
                # add Lenovo CacheInfo and CurrentClockSpeedMHz
                if ('Oem' in response_members_url.dict) and ('Lenovo' in response_members_url.dict['Oem']):
                    if ('CacheInfo' in response_members_url.dict['Oem']['Lenovo']):
                        cpu['CacheInfo'] = response_members_url.dict['Oem']['Lenovo']['CacheInfo']
                    if ('CurrentClockSpeedMHz' in response_members_url.dict['Oem']['Lenovo']):
                        cpu['CurrentClockSpeedMHz'] = response_members_url.dict['Oem']['Lenovo']['CurrentClockSpeedMHz']
                cpu_details.append(cpu)
            else:
                result = {'ret': False, 'msg': "response_members_url Error code %s" % response_members_url.status}

    result['ret'] = True
    result['entries'] = cpu_details
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result

import argparse
def add_parameter():
    """Add member parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--member', type=int,  help="Specify the member id to get only one member from list. 1 for first member, 2 for second, etc")
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['member'] = args.member
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    member_id = parameter_info['member']
    
    # Get cpu inventory and check result
    result = lenovo_get_cpu_inventory(ip, login_account, login_password, system_id, member_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
