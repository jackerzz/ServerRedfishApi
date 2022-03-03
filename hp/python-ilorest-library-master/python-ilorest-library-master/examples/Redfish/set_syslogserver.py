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
An example of set syslog server on HPE iLO Server.
"""
import sys
import json
import argparse
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError
global DISABLE_RESOURCE_DIR
from ilorest_util import get_resource_directory
from ilorest_util import get_gen

def set_syslog(_redfishobj, syslog_server):

    model_uri = "/redfish/v1/Systems/1/"
    model = _redfishobj.get(model_uri).obj['Model']
    print (model)
    if "Gen9" in model or 'Gen8' in model:
        hp = "Hp"
    else:
        hp = "Hpe"

    syslog_uri = "/redfish/v1/Managers/1/NetworkService/"

    body = {"Oem": {hp: {"RemoteSyslogServer": syslog_server, "RemoteSyslogEnabled": True}}}
    resp = _redfishobj.patch(syslog_uri, body)
    ilo_response(_redfishobj, resp)

def ilo_response(_redfishobj, resp):

    if resp.status == 400:
        try:
            print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4, \
                                                                         sort_keys=True))
        except Exception as excp:
            sys.stderr.write("A response error occurred, unable to access iLO Extended "\
                             "Message Info...")
    elif resp.status != 200:
        sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
    else:
        print("Success")

if __name__ == "__main__":
    # Initialize parser
    parser = argparse.ArgumentParser(description = "Script to upload and flash NVMe FW")

    parser.add_argument(
        '-i',
        '--ilo',
        dest='ilo_ip',
        action="store",
        help="iLO IP of the server",
        default=None)
    parser.add_argument(
        '-u',
        '--user',
        dest='ilo_user',
        action="store",
        help="iLO username to login",
        default=None)
    parser.add_argument(
        '-p',
        '--password',
        dest='ilo_pass',
        action="store",
        help="iLO password to log in.",
        default=None)
    parser.add_argument(
        '-s',
        '--syslog_server',
        dest='syslog_server',
        action="store",
        required=True,
        help="iLO password to log in.",
        default=None)

    options = parser.parse_args()

    system_url = "https://" + options.ilo_ip
    print (system_url)

    # flag to force disable resource directory. Resource directory and associated operations are
    # intended for HPE servers.
    DISABLE_RESOURCE_DIR = True

    try:
        # Create a Redfish client object
        redfish_obj = RedfishClient(base_url=system_url, username=options.ilo_user, password=options.ilo_pass)
        # Login with the Redfish client
        redfish_obj.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    (ilogen,_) = get_gen(redfish_obj)
    print ("Generation is ", ilogen)
    if int(ilogen) == 5:
        set_syslog(redfish_obj, options.syslog_server)
    else:
        set_syslog(redfish_obj, options.syslog_server)
    redfish_obj.logout()
