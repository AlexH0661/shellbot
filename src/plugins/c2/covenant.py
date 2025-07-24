import datetime
import json
import logging
import ssl

from requests import request

from utils import notifications

logger = logging.getLogger(__name__)
known_agents = []

# Configuration variables
api_token = None
user = None
password = None
host = None
port =  None

def api_auth(user, password):
    # Auth via POST to API endpoint: https://<host>:<port>/api/users/login
    url = f'https://{host}:{port}/api/users/login'
    login_info = {"userName": user, "password": password}

    try:
        req = request.Request(
            url,
            data=bytes(json.dumps(login_info), encoding='utf8'),
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
        )

        # Unverified context to allow Covenant self-signed cert
        response = request.urlopen(req, context=ssl._create_unverified_context())
    except BaseException as err:
        logger.error("Covenant Login Failed: %s", err)
        return None

    if response is not None:
        if response.getcode() == 200:
            if "application/json" in response.headers["content-type"]:
                resp_json = json.loads(response.read())
                if resp_json["success"]:
                    logger.info("Covenant Login Success, auth token acquired")
                    return resp_json["covenantToken"]
                else:
                    logger.error("Covenant Login Failed: Incorrect login information")
            else:
                logger.error("Covenant Login Failed: Unexpected response content-type")
        else:
            logger.error("Covenant Login Failed: Unexpected server response")

        return api_token
    else:
        logger.error("Covenant Login Failed: Server did not respond")
        return None


def check_agents():
    """
    Check for new covenant agents via API
    Example:
    [
        {
            "id": 1,
            "guid": "40d30e7dfb",
            "listenerId": 1,
            "userDomainName": "WINDEV2002EVAL",
            "userName": "User",
            "ipAddress": "192.168.136.129",
            "hostname": "WinDev2002Eval",
            "operatingSystem": "Microsoft Windows NT 10.0.18363.0",
            "activationTime": "2020-03-25T04:46:05.0951674",
            "lastCheckIn": "2020-03-25T04:56:38.228162",
        }
    ]
    """

    # Check for Grunts via GET to API endpoint: https://<host>:<port>/api/grunts
    url = f'https://{host}:{port}/api/grunts'
    req_headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {api_token}'
    }

    try:
        req = request.Request(url, headers=req_headers)

        # Unverified context to allow Covenant self-signed cert
        response = request.urlopen(req, context=ssl._create_unverified_context())
    except BaseException as err:
        logger.error("Covenant Grunt Check Failed: %s", err)
        return None

    if response is not None:
        if response.getcode() == 200:
            if "application/json" in response.headers["content-type"]:
                grunt_list = json.loads(response.read())
                if len(grunt_list) > 0:
                    logger.debug(f"Covenant Grunt Check: Grunt List\n{grunt_list}")
                    for grunt in grunt_list:
                        # Remove milliseconds from activation time because strptime can't deal with example
                        active_time = datetime.datetime.strptime(grunt["activationTime"].split('.')[0],
                                                                 '%Y-%m-%dT%H:%M:%S')
                        # Convert activation time to be timezone aware (UTC) and convert to local timezone
                        active_time_local = active_time.replace(tzinfo=datetime.timezone.utc).astimezone()

                        if grunt["guid"] not in known_agents["covenant"] and active_time_local > runTime.astimezone():
                            known_agents["covenant"].append(grunt["guid"])
                            logger.info(f"Covenant Grunt Check: New grunt checked in! GUID: {grunt['guid']}")
                            msg = f"Grunt Name: {grunt['name']}\nCheckin Time: {active_time_local}\n"
                            msg += f"System Info --\n"
                            msg += f"\tHostname: {grunt['hostname']}\n\tIP Addr: {grunt['ipAddress']}\n"
                            msg += f"\tDomain\\User: {grunt['userDomainName']}\\{grunt['userName']}\n"
                            msg += f"\tOS Info: {grunt['operatingSystem']}"
                            logger.info(f"Covenant Grunt Check: New Grunt details:\n{msg}")

                            notifications.send_new_agent_message_slack("Meterpreter", msg)
                            continue
                        else:
                            logger.debug(f"Covenant Grunt Check: Grunt ({grunt['guid']}) is already known about.")
                            continue
                else:
                    logger.debug("Covenant Grunt Check: No new grunts")
                    return
            else:
                logger.error("Covenant Grunt Check Failed: Unexpected response content-type")
        else:
            logger.error("Covenant  Grunt Check Failed: Unexpected server response")