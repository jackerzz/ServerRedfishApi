import sys
import json
from redfish import RedfishClient
from redfish.rest.v1 import ServerDownOrUnreachableError


def configure_snmp(_redfishobj):

    snmp_service_uri = None
    managers_uri = _redfishobj.root.obj['Managers']['@odata.id']
    managers_response = _redfishobj.get(managers_uri)
    managers_members_uri = next(iter(managers_response.obj['Members']))['@odata.id']
    managers_members_response = _redfishobj.get(managers_members_uri)
    # print(managers_members_response.obj['Oem']['Hpe']['Links'])
    # exit(0)
    snmp_service_uri = managers_members_response.obj.Oem.Hpe.Links['SNMPService']['@odata.id']

    if snmp_service_uri:
        # resp = _redfishobj.get(snmp_service_uri)
        # print(json.dumps(resp.dict, indent=4, sort_keys=True))
        # exit(0)
        # TrapSourceHostname : Manager or System
        body = {"TrapSourceHostname": "System"}
        resp = _redfishobj.patch(snmp_service_uri, body)

        if resp.status == 400:
            try:
                print(json.dumps(resp.obj['error']['@Message.ExtendedInfo'], indent=4,
                                 sort_keys=True))
            except Exception as excp:
                sys.stderr.write("A response error occurred, unable to access iLO Extended "
                                 "Message Info...")
        elif resp.status != 200:
            sys.stderr.write("An http response of \'%s\' was returned.\n" % resp.status)
        else:
            print("Success!\n")
            # print(json.dumps(resp.dict, indent=4, sort_keys=True))


if __name__ == "__main__":

    if len(sys.argv) <= 3:
        sys.stderr.write("ERROR: We need 3 arguments. \nUsage: change-snmp.py "
                         "ILOIPADDR ILOUSER ILOPASSWORD \n")
        sys.exit()

    SYSTEM_URL = "https://" + sys.argv[1]
    LOGIN_ACCOUNT = sys.argv[2]
    LOGIN_PASSWORD = sys.argv[3]

    try:
        REDFISHOBJ = RedfishClient(base_url=SYSTEM_URL, username=LOGIN_ACCOUNT,
                                   password=LOGIN_PASSWORD)
        REDFISHOBJ.login()
    except ServerDownOrUnreachableError as excp:
        sys.stderr.write("ERROR: server not reachable or does not support RedFish.\n")
        sys.exit()

    configure_snmp(REDFISHOBJ)
    REDFISHOBJ.logout()