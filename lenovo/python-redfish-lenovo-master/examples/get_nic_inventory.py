###
#
# Lenovo Redfish examples - Get the network information
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


def get_nic_inventory(ip, login_account, login_password, system_id):
    """Get nic inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns nic inventory when succeeded or error message when failed
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
    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get("/redfish/v1", None)
    if response_base_url.status == 200:
        chassis_url_list = response_base_url.dict['Chassis']['@odata.id']
    else:
        result = {'ret': False, 'msg': "get url %s failed. Error code %s" % ("/redfish/v1", response_base_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get Chassis collection
    response_chassis_url_list = REDFISH_OBJ.get(chassis_url_list, None)
    if response_chassis_url_list.status == 200:
        chassis_count = response_chassis_url_list.dict['Members@odata.count']
    else:
        result = {'ret': False, 'msg': "get url %s failed. Error code %s" % (chassis_url_list, response_chassis_url_list.status)}
        REDFISH_OBJ.logout()
        return result

    nic_details = []
    for count in range(chassis_count):
        # GET the Chassis resource
        chassis_url = response_chassis_url_list.dict['Members'][count]['@odata.id']
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status != 200:
            result = {'ret': False, 'msg': "get url %s failed. Error code %s" % (chassis_url, response_chassis_url.status)}
            REDFISH_OBJ.logout()
            return result

        # Skip this chassis if no NetworkAdapters found in it
        if "NetworkAdapters" not in response_chassis_url.dict:
            continue

        # GET the NetworkAdapters resource from the Chassis resource
        nic_adapter_url = response_chassis_url.dict["NetworkAdapters"]["@odata.id"]
        response_nic_adapter_url = REDFISH_OBJ.get(nic_adapter_url, None)
        if response_nic_adapter_url.status == 200:
            nic_adapter_count = response_nic_adapter_url.dict["Members@odata.count"]
        else:
            result = {'ret': False,
                      'msg': "get url %s failed. Error code %s" % (nic_adapter_url, response_nic_adapter_url.status)}
            REDFISH_OBJ.logout()
            return result

        for nic in range(0, nic_adapter_count):
            network = {}
            nic_adapter_x_url = response_nic_adapter_url.dict["Members"][nic]["@odata.id"]
            response_nic_adapter_x_url = REDFISH_OBJ.get(nic_adapter_x_url, None)
            if response_nic_adapter_x_url.status != 200:
                result = {'ret': False,
                          'msg': "get url %s failed. Error code %s" % (nic_adapter_x_url, response_nic_adapter_x_url.status)}
                REDFISH_OBJ.logout()
                return result

            for property in ['Id', 'Name', 'Status', 'Manufacturer', 'Model', 'PartNumber', 'SKU', 'SerialNumber']:
                if property in response_nic_adapter_x_url.dict:
                    network[property] = response_nic_adapter_x_url.dict[property]
            if "Controllers" not in response_nic_adapter_x_url.dict:
                continue

            # get Controller info including NetworkDeviceFunctions and assigned port in Controller
            controller_list = []
            for controller in response_nic_adapter_x_url.dict["Controllers"]:
                nic_devices = []
                controller_data = {}
                for property in ['FirmwarePackageVersion', 'ControllerCapabilities']:
                    if property in controller:
                        controller_data[property] = controller[property]

                # get the NetworkDeviceFunction resources
                if ("Links" not in controller) or ("NetworkDeviceFunctions" not in controller["Links"]):
                    continue
                for devfun in controller["Links"]["NetworkDeviceFunctions"]:
                    NIC_Devices = {}
                    nic_dev_x_url = devfun["@odata.id"]
                    response_nic_dev_x_url = REDFISH_OBJ.get(nic_dev_x_url, None)
                    if response_nic_dev_x_url.status != 200:
                        result = {'ret': False,
                                  'msg': "get url %s failed. Error code %s" % (nic_dev_x_url, response_nic_dev_url.status)}
                        REDFISH_OBJ.logout()
                        return result

                    for property in ['Id', 'Name', 'NetDevFuncType', 'DeviceEnabled', 'Ethernet', 'Status']:
                        if property in response_nic_dev_x_url.dict:
                            NIC_Devices[property] = response_nic_dev_x_url.dict[property]

                    # GET the associated NetworkPort resource
                    if "PhysicalPortAssignment" in response_nic_dev_x_url.dict:
                        nic_port_x_url = response_nic_dev_x_url.dict["PhysicalPortAssignment"]["@odata.id"]
                        response_nic_port_x_url = REDFISH_OBJ.get(nic_port_x_url, None)
                        if response_nic_port_x_url.status == 200:
                            Physical_Ports = {}
                            for property in ['PhysicalPortNumber', 'Name', 'ActiveLinkTechnology', 'PortMaximumMTU', 'Status', 'LinkStatus']:
                                if property in response_nic_port_x_url.dict:
                                    Physical_Ports[property] = response_nic_port_x_url.dict[property]
                            NIC_Devices['physical_port'] = Physical_Ports
                        else:
                            result = {'ret': False,
                                      'msg': "get url %s failed. Error code %s" % (nic_port_x_url, response_nic_port_x_url.status)}
                            REDFISH_OBJ.logout()
                            return result
                    nic_devices.append(NIC_Devices)

                controller_data['NetworkDeviceFunctions'] = nic_devices
                controller_list.append(controller_data)
            network['Controllers'] = controller_list
            nic_details.append(network)

    # if no info got from chassis, get info from /redfish/v1/Systems/{ComputerSystemId}/EthernetInterfaces/{EthernetInterfaceId}
    if len(nic_details) == 0:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            REDFISH_OBJ.logout()
            return result
        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the EthernetInterfaces url
                if 'EthernetInterfaces' not in response_system_url.dict:
                    continue
                else:
                    nic_adapter_url = response_system_url.dict['EthernetInterfaces']['@odata.id']
            else:
                result = {'ret': False, 'msg': "get url %s failed. Error code %s" % (system_url, response_system_url.status)}
                REDFISH_OBJ.logout()
                return result

            response_nic_adapter_url = REDFISH_OBJ.get(nic_adapter_url, None)
            if response_nic_adapter_url.status == 200:
                nic_adapter_count = response_nic_adapter_url.dict["Members@odata.count"]
            else:
                result = {'ret': False,
                          'msg': "get url %s failed. Error code %s" % (nic_adapter_url, response_nic_adapter_url.status)}
                REDFISH_OBJ.logout()
                return result

            for nic in range(0, nic_adapter_count):
                network = {}
                nic_adapter_x_url = response_nic_adapter_url.dict["Members"][nic]["@odata.id"]
                response_nic_adapter_x_url = REDFISH_OBJ.get(nic_adapter_x_url, None)
                if response_nic_adapter_x_url.status != 200:
                    result = {'ret': False,
                              'msg': "get url %s failed. Error code %s" % (nic_adapter_x_url, response_nic_adapter_x_url.status)}
                    REDFISH_OBJ.logout()
                    return result

                # Get the nic info
                for property in ['Id', 'Name', 'MACAddress', 'MTUSize', 'FQDN', 'AutoNeg', 'Status']:
                    if property in response_nic_adapter_x_url.dict:
                        network[property] = response_nic_adapter_x_url.dict[property]
                nic_details.append(network)
                continue

    result['ret'] = True
    result['entries'] = nic_details
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get nic inventory and check result
    result = get_nic_inventory(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
