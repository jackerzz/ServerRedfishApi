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
An example of uploading firmware to the iLO Repository for flashing
"""

import os
import sys
import json
import argparse
from random import randint

from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
import logging
from redfish import redfish_logger

from ilorest_util import get_resource_directory

LOGGERFILE = "RedfishApiExamples.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGGER = redfish_logger(LOGGERFILE, LOGGERFORMAT, logging.DEBUG)

def upload_firmware(_redfishobj, firmware_loc, comp_type, update_repo=True, update_target=False):
    resource_instances = get_resource_directory(_redfishobj)

    if DISABLE_RESOURCE_DIR or not resource_instances:
        #resource directory is not available so we will navigate through paths manually
        update_service_uri = _redfishobj.root.obj['UpdateService']['@odata.id']
    else:
        #obtain all account instances from resource directory
        for instance in resource_instances:
            if '#UpdateService.' in instance['@odata.type']:
                update_service_uri = instance['@odata.id']

    print (update_service_uri)

    update_service_response = _redfishobj.get(update_service_uri)

    path = update_service_response.obj.HttpPushUri
    print (path)

    body = []

    json_data = {'UpdateRepository': update_repo, 'UpdateTarget': update_target, 'ETag': 'atag', 'Section': 0}
    session_key = _redfishobj.session_key

    #ImageLocation = "c:\\test"
    #filename = "I41_2.40_08_10_2020.fwpkg"
    #ImagePath = os.path.join(ImageLocation, filename)
    #file_name = os.path.basename(firmware_loc)
    #print (ImagePath)
    with open(firmware_loc, 'rb') as fle:
        output = fle.read()

    session_tuple = ('sessionKey', session_key)
    parameters_tuple = ('parameters', json.dumps(json_data))
    file_tuple = ('file', (filename, output, 'application/octet-stream'))

    #Build the payload from each multipart-form data tuple
    body.append(session_tuple)
    body.append(parameters_tuple)
    body.append(file_tuple)
    #print (body)

    #Create our header dictionary
    header = {'Cookie': 'sessionKey=' + session_key}

    print ('Begin upload....please wait...')
    # We pass the whole list payload to post
    resp = _redfishobj.post(path, body, headers=header)

    if resp.status == 400:
        sys.stderr.write("Failed to upload firmware...")
    elif not resp.status in [200, 201]:
        sys.stderr.write("An http response of '%s' was returned.\n" % resp.status)
    else:
        print("Upload complete!\n")


def create_task(_redfishobj, firmware_loc, tpm_flag=True):

    session_key = _redfishobj.session_key
    #Create our header dictionary
    header = {'Cookie': 'sessionKey=' + session_key}

    updatable_by = ['Uefi']
    task_path = '/redfish/v1/UpdateService/UpdateTaskQueue/'
    file_name = os.path.basename(firmware_loc)

    task_resp = _redfishobj.get(task_path)
    if not task_resp.obj["Members@odata.count"]:
        print ("No current tasks, proceed to create new task")


    update_task = {'Name': 'Update-%s-%s' % (str(randint(0, 1000000)), \
                        file_name), 'Command': 'ApplyUpdate',\
                      'Filename': file_name, 'UpdatableBy': updatable_by, 'TPMOverride': tpm_flag}

    resp = _redfishobj.post(task_path, update_task, headers=header)
    #print (resp)
    if resp.status == 400:
        sys.stderr.write("Failed to create update task queue...")
    elif not resp.status in [200, 201]:
        sys.stderr.write("An http response of '%s' was returned.\n" % resp.status)
    else:
        print("Task Queue Creation complete!\n")


if __name__ == "__main__":

    # Initialize parser
    parser = argparse.ArgumentParser(description = "Script to upload and flash NVMe FW")

    parser.add_argument(
        '-c',
        '--component',
        dest='comp_path',
        action="store",
        required=True,
        help="The path to the firmware file to upload",
        default=None)
    parser.add_argument(
        '-s',
        '--session_key',
        dest='session_key',
        action="store",
        required=False,
        help="Http session key for the server",
        default=None)
    parser.add_argument(
        '-i',
        '--ilo',
        dest='ilo_ip',
        action="store",
        required=False,
        help="iLO IP of the server",
        default=None)
    parser.add_argument(
        '-u',
        '--user',
        dest='ilo_user',
        action="store",
        required=False,
        help="iLO username to login",
        default=None)
    parser.add_argument(
        '-p',
        '--password',
        dest='ilo_pass',
        action="store",
        required=False,
        help="iLO password to log in.",
        default=None)

    options = parser.parse_args()

    system_url = "https://" + options.ilo_ip
    print (system_url)

    # Upload the firmware file to the iLO Repository
    update_repo_flag = True
    # Update the system with the firmware file
    update_target_flag = False

    comp_type = 'C'
    tpm_flag = True

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = True
    #system_url = "https://" + "15.146.46.49"
    #session_id = "515b196969f7d879886ee4a2da4ccba8"

    try:
        # Create a Redfish client object
        if options.session_key:
            redfish_obj = RedfishClient(base_url=system_url, session_key= options.session_key)
        else:
            redfish_obj = RedfishClient(base_url=system_url, username=options.ilo_user, password=options.ilo_pass)
        # Login with the Redfish client
        redfish_obj.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    upload_firmware(redfish_obj, options.comp_path, comp_type, update_repo_flag, update_target_flag)
    if comp_type == 'C':
        create_task(redfish_obj, options.comp_path, tpm_flag)

    redfish_obj.logout()
