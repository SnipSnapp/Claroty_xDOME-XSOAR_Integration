register_module_line('Claroty_XDome', 'start', __line__())
#Author: Harrison Koll April 2023, https://github.com/SnipSnapp/Claroty_xDOME-XSOAR_Integration/edit/main/integration.py
'''IMPORTS'''
import requests
import urllib3
from datetime import datetime,timezone,timedelta
'''GLOBALS/PARAMS'''
#suppress SSL warning, this is so we don't get a red text output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
INTEGRATION_NAME='Claroty xDome'
#Get the API token
SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')
ALERT_URL = demisto.params().get('tenant_url')
#set the alerts URL
API_ALERTS_URL = "https://api.claroty.com/api/v1/alerts/"
#Set our API token per the API documentation
TOKEN_HEADER = {"Authorization": f"Bearer {SECRET}"}
#Fetch alerts at a designated interval of 1 minute
FETCH_INTERVAL = datetime.now(tz=timezone(timedelta(hours=-5), name="CDT")) - timedelta(minutes=
int(demisto.params().get('incidentFetchInterval')))
'''KEY DICTIONARY'''
#Used for fetching detections. This is the JSON needed
DETECTIONS_ALERTS_KEY_MAP = {
            "offset": 0,
            "limit": 100,
            "filter_by": {
                "operation":"and",
                "operands":[
                    {
                    "field": "updated_time",
                    "operation": "greater_or_equal",
                    "value": str(FETCH_INTERVAL),
                    },
                    {
                    "field": "category",
                    "operation": "in",
                    "value": ["Threat","Custom"]
                    }
                ]

            },
            "fields": [
                "id",
                "alert_name",
                "alert_type_name",
                "alert_class",
                "category",
                "status"
            ]
        }

#Used for fetching the devices affected by a detection. This is the JSON needed & the fields that are retrieved.
DETECTIONS_ALERT_DEVICE_KEY_MAP = {
        "offset":0,
        "limit":100,
        "filter_by":{
            "field":"is_resolved",
            "operation":"in",
            "value":["False"]
        },
        "fields":[
            "endpoint_security_names",
            "dhcp_hostnames",
            "http_hostnames",
            "snmp_hostnames",
            "windows_hostnames",
            "other_hostnames",
            "os_name",
            "os_version",
            "os_revision",
            "combined_os",
            "device_category",
            "device_type",
            "ip_list",
            "consequence_of_failure",
            "vlan_name_list",
            "switch_ip_list",
            "manufacturer",
            "infected",
            "authentication_user_list",
            "is_resolved",
            "last_domain_user",
            "edr_is_up_to_date_text",
            "endpoint_security_names",
            "labels"

        ]

    }
'''API FUNCTIONS'''
#Pull any alerts that have occurred in the past minute.
def get_alerts():
    """
    :return: an array of JSON elements, for the alerts that have been pulled in the last update interval minute.
    """
    alert_return = []
    alerts_json = requests.post(url=API_ALERTS_URL, json=DETECTIONS_ALERTS_KEY_MAP, headers=TOKEN_HEADER,
    verify=False).json()['alerts']
    if alerts_json is None or len(alerts_json) ==0:
        return alert_return
    for alert in alerts_json:
        if alert['status'] == 'Unresolved':
            for y in alert:
                alert.update({y:str(alert[y])})
            alert.update({'device_details':fetch_affected_devices({'alert_id': alert['id']})})
            alert.update({'alert_link':f'{ALERT_URL}/alerts-and-threats/alerts/{alert["id"]}#details'})
            alert.update({'inc_class':'xDome'})
            the_data=json.dumps(alert,indent=4)
            alert_return.append({
                'name':alert['alert_name'],
                'occurred':datetime.now(timezone.utc).astimezone().isoformat(),
                'dbotMirrorId':alert['id'],
                'rawJSON':the_data
                })

    return alert_return

#Pull any devices that are affected by an alert (by the alert ID)
def fetch_affected_devices(args : dict):
    """
    :param alert_id: the alert ID number that the list of affected devices will pull from
    :return: JSON output of what devices were pulled from an alert.
    """
    alert_return = []
    if not args.get('alert_id'):
        raise DemistoException('Please add a filter argument "alert_id".')

    fetch_url = f"{API_ALERTS_URL}{args.get('alert_id')}/devices"
    for alert in requests.post(url=fetch_url, json=DETECTIONS_ALERT_DEVICE_KEY_MAP, headers=TOKEN_HEADER,
    verify=False).json()["devices"]:
        alert_return.append(alert)
    return alert_return

def test_module():
    try:
        test = get_alerts()
        if test != None:
            return 'ok'
    except Exception as e:
        return e
    return test

#Check the command being pushed to this integration
def main():
    command = demisto.command()
    if command == 'fetch-incidents' :
        #demisto.createincidents(get_alerts())
        demisto.incidents(get_alerts())
    elif command== 'xdome-fetch-incidents':
        for y in get_alerts():
            return_results(y)

    elif command == 'xdome-fetch-alert-details':
        demisto.results( fetch_affected_devices(demisto.args()))
    elif command == 'test-module':
        return_results(test_module())

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('Claroty_XDome', 'end', __line__())
