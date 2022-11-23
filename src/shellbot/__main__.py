#!/usr/bin/env python3

__author__ = "Russel Van Tuyl"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__updated__ = "AlexH0661"
__version__ = "2.0.0"

import sqlite3
import datetime
import urllib3
import time
import sys
import os
import argparse
import json
import signal
import socket
import subprocess
import ssl
from collections import defaultdict
import logging
import datetime
import msgpack
import yaml

parser = argparse.ArgumentParser()
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    default=False,
    help="Enable verbose/debug output to console",
)
args = parser.parse_args()

cur_datetime = datetime.datetime.now()
formatted_datetime = cur_datetime.strftime("%Y-%m-%d-%H%M%S")
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s / %(levelname)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename=f"logs/{formatted_datetime}.log",
    filemode="w",
)
console = logging.StreamHandler()
if args.verbose:
    console.setLevel(logging.DEBUG)
else:
    console.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)
logger = logging.getLogger("")

#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m[-]\033[0m "
warn = "\033[0;0;31m[!]\033[0m "
info = "\033[0;0;36m[i]\033[0m "
question = "\033[0;0;37m[?]\033[0m "
debug = "\033[0;0;31m[DEBUG]\033[0m "
check_in = "\033[0;0;92m[+]\033[0m "

ssb_root = os.path.dirname(os.path.realpath(__file__))
runTime = datetime.datetime.now()
sleepTime = 60
slackHook = None
teamsHook = None
botName = None
discordHook = None
channel = None
empireDb = None
poshc2Db = None
msfRpcHost = "127.0.0.1"
msfRpcPort = "55552"
msfRpcUser = "msf"
msfRpcPass = None
msfRpcToken = None
covApiToken = None
knownAgents = {"empire": [], "msf": [], "covenant": [], "poshc2": []}
host_name = ""
host_ip = ""


def ascii_art():
    art = "\033[0;0;36m"
    art += r"""
 __________
< ShellBot >
 ----------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
"""
    art += "\033[0m"
    art += """
Author: {0}
Maintainer: {1}
Email: {2}
Last Updated By: {3}
Version: {4}

""".format(
        __author__, __maintainer__, __email__, __updated__, __version__
    )
    print(art)


def get_IP():
    """
    Gets the public IP address of the host, as well as other identifying data,
    such as hostname and country and region.

    :returns list: host IP address, host geographic location, hostname
    """
    http = urllib3.PoolManager()
    r = http.request("GET", "http://ip-api.com/json")
    response_dict = json.loads(r.data.decode("utf-8"))
    host_ip = response_dict["query"]
    host_location = response_dict["country"] + ", " + response_dict["regionName"]
    host_name = socket.gethostname()
    logger.debug(host_name)
    logger.debug(host_ip)
    logger.debug(host_location)
    return host_ip, host_location, host_name


def decode_list(l):
    result = []
    for item in l:
        if isinstance(item, bytes):
            result.append(item.decode())
            continue
        if isinstance(item, list):
            result.append(decode_list(item))
            continue
        if isinstance(item, dict):
            result.append(decode_dict(item))
            continue
        result.append(item)
    return result


def decode_dict(d):
    result = {}
    for key, value in d.items():
        if isinstance(key, bytes):
            key = key.decode()
        if isinstance(value, bytes):
            value = value.decode()
        if isinstance(value, list):
            value = decode_list(value)
        elif isinstance(value, dict):
            value = decode_dict(value)
        result.update({key: value})
    return result


def post_msg_discord(msg, status=None, colour="15776264"):
    data = {}
    data["tts"] = "true"
    data["username"] = "ShellBot - " + host_name
    data[
        "avatar_url"
    ] = "https://cdn3.vectorstock.com/i/1000x1000/78/02/cartoon-turtle-vector-4367802.jpg"
    data["embeds"] = []
    embed = {}
    embed["color"] = colour
    embed["title"] = "ShellBot {0} on {1}".format(status, host_ip)
    embed["description"] = msg
    data["embeds"].append(embed)
    req = request.Request(discordHook, data=bytes(json.dumps(data), "UTF-8"))
    req.add_header("Content-Type", "application/json")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363",
    )
    response = request.urlopen(req)
    logger.debug("Server response: {}".format(response.getcode()))


def post_msg_slack(msg, status=None):
    total_data = {}
    total_data["username"] = "ShellBot - {}".format(host_name)
    total_data["icon_emoji"] = ":shellbot:"
    total_data["text"] = msg
    total_data["blocks"] = []
    data = defaultdict(dict)
    data["type"] = "section"
    data["text"]["type"] = "mrkdwn"
    data["text"]["text"] = "{0}\r\n```ShellBot {1} on {2}```".format(
        msg, status, host_ip
    )
    total_data["blocks"].append(data)
    req = request.Request(slackHook, data=bytes(json.dumps(total_data), "UTF-8"))
    req.add_header("Content-Type", "application/json")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363",
    )
    response = request.urlopen(req)
    logger.debug("Server response: {}".format(response.getcode()))


def db_query(dbPath):
    """Query sqlite database"""

    agents = {}

    try:
        connection = sqlite3.connect(dbPath)
        rs = connection.execute(
            "SELECT session_id, checkin_time, name, external_ip, internal_ip, username, hostname, "
            "os_details, high_integrity, process_name, process_id FROM agents;"
        )

        for r in rs:
            agents[r[0]] = {
                "checkin_time": r[1],
                "session_id": r[0],
                "name": r[2],
                "external_ip": r[3],
                "internal_ip": r[4],
                "username": r[5],
                "hostname": r[6],
                "os_details": r[7],
                "high_integrity": str(r[8]),
                "process_name": r[9],
                "process_id": r[10],
            }

        connection.close()
    except sqlite3.OperationalError as e:
        logger.warning("Error connecting to the database at {}".format(dbPath))
        print(e)

    return agents


def poshc2_db_query(dbPath):
    """Query PoshC2 sqlite database"""
    try:
        connection = sqlite3.connect(dbPath)
        rows = connection.execute("SELECT * FROM Implants;")
        agents = defaultdict(dict)

        for row in rows:
            if len(row) > 17:
                agents[ImplantIndex]["ImplantIndex"] = row[0]
                agents[ImplantIndex]["ImplantID"] = row[1]
                agents[ImplantIndex]["RandomURI"] = row[2]
                agents[ImplantIndex]["URLID"] = row[3]
                agents[ImplantIndex]["User"] = row[4]
                agents[ImplantIndex]["Hostname"] = row[5]
                agents[ImplantIndex]["IpAddress"] = row[6]
                agents[ImplantIndex]["Key"] = row[7]
                agents[ImplantIndex]["FirstSeen"] = row[8]
                agents[ImplantIndex]["LastSeen"] = row[9]
                agents[ImplantIndex]["PID"] = row[10]
                agents[ImplantIndex]["Arch"] = row[11]
                agents[ImplantIndex]["Domain"] = row[12]
                agents[ImplantIndex]["Alive"] = row[13]
                agents[ImplantIndex]["Sleep"] = row[14]
                agents[ImplantIndex]["ModsLoaded"] = row[15]
                agents[ImplantIndex]["Pivot"] = row[16]
                agents[ImplantIndex]["Label"] = row[17]
            elif len(row) == 17:
                ImplantIndex = row[0]
                agents[ImplantIndex]["ImplantID"] = row[1]
                agents[ImplantIndex]["RandomURI"] = "NaN"
                agents[ImplantIndex]["URLID"] = row[2]
                agents[ImplantIndex]["User"] = row[3]
                agents[ImplantIndex]["Hostname"] = row[4]
                agents[ImplantIndex]["IpAddress"] = row[5]
                agents[ImplantIndex]["Key"] = row[6]
                agents[ImplantIndex]["FirstSeen"] = row[7]
                agents[ImplantIndex]["LastSeen"] = row[8]
                agents[ImplantIndex]["PID"] = row[9]
                agents[ImplantIndex]["Arch"] = row[10]
                agents[ImplantIndex]["Domain"] = row[11]
                agents[ImplantIndex]["Alive"] = row[12]
                agents[ImplantIndex]["Sleep"] = row[13]
                agents[ImplantIndex]["ModsLoaded"] = row[14]
                agents[ImplantIndex]["Pivot"] = row[15]
                agents[ImplantIndex]["Label"] = row[16]
        connection.close()
    except sqlite3.OperationalError as e:
        logger.warning("Error connecting to the database at {}".format(dbPath))
        print(e)

    return agents


def msf_rpc_request(payload):
    # Make HTTP POST Request to MSF RPC Interface

    url = "http://" + msfRpcHost + ":" + msfRpcPort + "/api/1.1"
    try:
        req = request.Request(
            url, data=payload, headers={"content-type": "binary/message-pack"}
        )
        response = request.urlopen(req)
        return response

    except BaseException as e:
        logger.warning(e)
        logger.warning(
            "ShellBot will continue without Metasploit because it was unable to communicate with the RPC server at {}".format(
                url
            )
        )
        logger.info("try 'load msgrpc` in your currently running Metasploit Instance")
        logger.info(
            "Visit https://help.rapid7.com/metasploit/Content/api-rpc/getting-started-api.html for additional information"
        )
        return None


def msf_rpc_get_temp_auth_token():
    # Get a temporary authentication token from the Metasploit RPC Server

    global msfRpcToken

    payload = msgpack.packb(["auth.login", msfRpcUser, msfRpcPass])
    response = msf_rpc_request(payload)
    try:
        content = msgpack.unpackb(response.read())
        content = decode_dict(content)
    except BaseException as e:
        if str(e) == None:
            exit(1)
    if response is not None:
        if args.verbose:
            logger.debug(
                "MSF RPC auth.login response:\n\tHTTP Status Code: {}".format(
                    response.getcode()
                )
            )
            if response.headers["Content-Type"] == "binary/message-pack":
                msf_rpc_message = content
                logger.debug("MSF RPC Server Response: {}".format(msf_rpc_message))
                if "error" in msf_rpc_message.keys():
                    logger.debug(
                        "MSF RPC Error: {}".format(msf_rpc_message["error_message"])
                    )
            else:
                logger.debug("HTTP Server Response: {}".format(content))
        if response.getcode() == 200:
            if "error" in content.keys():
                logger.warning("MSF RPC Error: {}".format(content["error_message"]))
                logger.warning("Quitting")
                sys.exit()
            elif "token" in content.keys():
                msfRpcToken = content["token"]


def cov_api_auth(user, password):

    # Auth via POST to API endpoint: https://<host>:<port>/api/users/login
    url = f"https://{covHost}:{covPort}/api/users/login"
    login_info = {"userName": user, "password": password}

    try:
        req = request.Request(
            url,
            data=bytes(json.dumps(login_info), encoding="utf8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
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

        return covApiToken
    else:
        logger.error("Covenant Login Failed: Server did not respond")
        return None


def msf_rpc_get_session_list():
    # Get a list of Meterpreter sessions

    payload = msgpack.packb(["session.list", msfRpcToken])
    response = msf_rpc_request(payload)
    content = msgpack.unpackb(response.read())
    content = decode_dict(content)
    if response is not None:
        if response.getcode() == 200:
            return content
        else:
            return None
    else:
        return None


def send_new_agent_message_discord(agentType, payload):
    data = defaultdict(lambda: defaultdict(dict))
    embed = {}
    # Send New Agent Message to Discord
    if args.verbose:
        logger.debug(
            "New Discord agent message agent: {0}, payload: {1}".format(
                agentType, payload
            )
        )

    if agentType == "Meterpreter":
        data["tts"] = True
        data[
            "avatar_url"
        ] = "https://ih1.redbubble.net/image.65324534.3912/raf,750x1000,075,t,fafafa:ca443f4786.u5.jpg"
        data["content"] = "New Metasploit Session"
        data["username"] = "ShellBot - " + host_name
        data["embeds"] = []
        embed["color"] = 1108193
        embed["description"] = "Implant Details"
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        embed["fields"] = []
        fields = {"name": "Implant", "value": payload, "inline": True}
        embed["fields"].append(fields)
        data["embeds"].append(embed)

    elif agentType == "Empire":
        data[
            "avatar_url"
        ] = "https://avatars2.githubusercontent.com/u/25492515?s=400&v=4"
        data["content"] = "New Empire Session"
        data["username"] = "ShellBot - " + host_name
        data["tts"] = True
        data["embeds"] = []
        embed["color"] = 1108193
        embed["description"] = payload
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        embed["fields"] = []
        fields = {"name": "Implant", "value": payload, "inline": True}
        embed["fields"].append(fields)
        data["embeds"].append(embed)

    elif agentType.lower() == "covenant":
        data[
            "avatar_url"
        ] = "https://raw.githubusercontent.com/wiki/cobbr/Covenant/covenant.png"
        data["content"] = "New Covenant Session"
        data["username"] = "ShellBot - " + host_name
        data["tts"] = True
        data["embeds"] = []
        embed["color"] = 1108193
        embed["description"] = "Implant Details"
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        embed["fields"] = []
        for k, v in payload.items():
            fields = {}
            fields["name"] = f"{k}"
            fields["value"] = f"{v}"
            fields["inline"] = True
            embed["fields"].append(fields)
        data["embeds"].append(embed)

    elif agentType.lower() == "poshc2":
        data[
            "avatar_url"
        ] = "https://raw.githubusercontent.com/nettitude/PoshC2/master/resources/images/PoshC2Logo.png"
        data["content"] = "New PoshC2 Session"
        data["username"] = "ShellBot - " + host_name
        data["tts"] = True
        data["embeds"] = []
        embed["color"] = 1108193
        embed["description"] = "Implant Details"
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        embed["fields"] = []
        for k, v in payload.items():
            fields = {}
            fields["name"] = f"{k}"
            fields["value"] = f"{v}"
            fields["inline"] = True
            embed["fields"].append(fields)
        data["embeds"].append(embed)

    logger.debug(data)
    req = request.Request(discordHook, data=bytes(json.dumps(data), "UTF-8"))
    req.add_header("Content-Type", "application/json")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
    )
    response = request.urlopen(req)
    if args.verbose:
        logger.debug("{}".format(response.read().decode()))
        logger.debug("{}".format(response.getcode()))
    if response.getcode() == 204 or response.getcode() == 200:
        print(
            check_in
            + "New {} agent check in successfully posted to Discord".format(agentType)
        )
    else:
        logger.warning(
            "Message not posted to Discord. HTTP Status Code: {}".format(
                response.getcode()
            )
        )


def send_new_agent_message_slack(agentType, payload):
    # Send New Agent Message to Slack
    if args.verbose:
        logger.debug(
            "New Slack agent message agent: {0}, payload: {1}".format(
                agentType, payload
            )
        )
    text = "```[+] New {0} agent check in to {1}\n{2}```".format(
        agentType, host_ip, payload
    )
    if agentType == "Meterpreter":
        total_data = {}
        total_data["channel"] = channel
        total_data["username"] = "ShellBot - {}".format(host_name)
        total_data["icon_emoji"] = ":metasploit:"
        total_data["text"] = "Woo!"
        total_data["blocks"] = []
        data = defaultdict(dict)
        data["type"] = "section"
        data["text"]["type"] = "mrkdwn"
        data["text"]["text"] = text
        total_data["blocks"].append(data)

    elif agentType == "Empire":
        total_data = {}
        total_data["channel"] = channel
        total_data["username"] = "ShellBot - {}".format(host_name)
        total_data["icon_emoji"] = ":empire:"
        total_data["text"] = "Woo!"
        total_data["blocks"] = []
        data = defaultdict(dict)
        data["type"] = "section"
        data["text"]["type"] = "mrkdwn"
        data["text"]["text"] = text
        total_data["blocks"].append(data)

    elif agentType.lower() == "covenant":
        total_data = {}
        total_data["channel"] = channel
        total_data["username"] = "ShellBot - {}".format(host_name)
        total_data["icon_emoji"] = ":covenant:"
        total_data["text"] = "Woo!"
        total_data["blocks"] = []
        data = defaultdict(dict)
        data["type"] = "section"
        data["text"]["type"] = "mrkdwn"
        data["text"]["text"] = text
        total_data["blocks"].append(data)

    elif agentType.lower() == "poshc2":
        total_data = {}
        total_data["channel"] = channel
        total_data["username"] = "ShellBot - {}".format(host_name)
        total_data["icon_emoji"] = ":poshc2:"
        total_data["text"] = "Woo!"
        total_data["blocks"] = []
        data = defaultdict(dict)
        data["type"] = "section"
        data["text"]["type"] = "mrkdwn"
        data["text"]["text"] = text
        total_data["blocks"].append(data)

    logger.debug(total_data)
    req = request.Request(slackHook, data=bytes(json.dumps(total_data), "UTF-8"))
    req.add_header("Content-Type", "application/json")
    req.add_header(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363",
    )
    response = request.urlopen(req)

    if args.verbose:
        logger.debug("{}".format(response.read()))
        logger.debug("{}".format(response.getcode()))
    if response.getcode() == 200:
        print(
            check_in
            + "New {} agent check in successfully posted to Slack".format(agentType)
        )
        logger.info("{}".format(payload.replace("\n", ", ")))
    else:
        logger.warning(
            "Message not posted to Slack. HTTP Status Code: {0}".format(
                response.getcode()
            )
        )


def send_new_agent_message_teams(agentType, payload):
    # Send a Microsoft Teams Activity Card HTTP POST message to a web hook

    if args.verbose:
        logger.debug(
            "New Microsoft Teams agent message agent: {0}, payload: {1}".format(
                agentType, payload
            )
        )

    data = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "[+] New {0} agent check in".format(agentType),
        "title": "[+] New {1} agent check in".format(agentType),
        "themeColor": "FF1000",
        "sections": [
            {"text": "I smell pwnage in the air..."},
            {"facts": [{"name": "Agent Type", "value": agentType}]},
        ],
    }

    for p in payload:
        data["sections"][1]["facts"].append({"name": p, "value": payload[p]})

    data_msg = parse.urlencode(data).encode()
    req = request.Request(
        teamsHook, data=data_msg, headers={"content-type": "application/json"}
    )
    response = request.urlopen(req)

    if args.verbose:
        logger.debug(response.text)
        logger.debug("{}".format(response.getcode()))
        logger.debug("{}".format(data))
    if response.getcode() == 200:
        print(
            check_in
            + "New {0} agent check in successfully posted to Microsoft Teams".format(
                agentType
            )
        )
        if agentType == "Empire":
            logger.info(
                "Agent ID: {0}, Checkin Time: {1}".format(
                    payload.get("session_id"), payload.get("checkin_time")
                )
            )
        elif agentType == "Meterpreter":
            logger.info(
                "Meterpreter UUID: {0}, Info: {1}".format(
                    payload.get("uuid"), payload.get("info")
                )
            )
    else:
        logger.warning(
            "Message not posted to Microsoft Teams. HTTP Status Code: {}".format(
                response.getcode()
            )
        )


def parse_config():
    """
    parses config.yaml file
    :returns: config dict
    """

    global sleepTime
    global slackHook
    global botName
    global channel
    global discordHook
    global empireDb
    global msfRpcHost
    global msfRpcPort
    global msfRpcUser
    global msfRpcPass
    global covHost
    global covPort
    global covApiToken
    global teamsHook
    global poshc2Db

    if args.verbose:
        logger.debug("Parsing config file")

    with open("config.yaml", "r") as fp:
        config = yaml.safe_load(fp)

    # This count is used to keep track of how many notification services we failed to connected to
    count = 0

    # Config for publishing notifications
    try:
        slackHook = config["slack"]["slackHook"]
        botName = config["slack"]["botName"]
        channel = config["slack"]["channel"]
        logger.info("Using Slack for notifications")
    except KeyError:
        logger.debug("Slack integration not defined.")
        count += 1
        pass

    try:
        discordHook = config["discord"]["discordHook"]
        logger.info("Using Discord for notifications")
    except KeyError as key_err:
        logger.debug("Discord Web Hook was not provided")
        count += 1
        pass

    try:
        teamsHook = config["teams"]["teamsHook"]
        logger.info("Using Microsoft Teams for notifications")
    except KeyError as key_err:
        logger.debug("Microsoft Teams Web Hook was not provided")
        count += 1
        pass

    if count == 3:
        logger.critical("No notification providers available. Exiting")
        sys.exit(1)

    # This section can be missing, will use default values instead
    sleepTime = int(config["ShellBot"].get("sleepTime", 60))

    count = 0
    # Parse Empire config
    try:
        e = config["empire"]["db"]
        if os.path.isfile(os.path.join(ssb_root, e)):
            empireDb = os.path.join(ssb_root, e)
    except KeyError:
        logger.warning(
            "ShellBot will continue without Empire because configuration was not provided."
        )
        count += 1

    # Parse PoshC2 config
    try:
        if bool(config["posh"]["enabled"]):
            with open("/var/poshc2/CURRENT_PROJECT", "r") as CP:
                CURRENT_PROJECT = CP.readline().strip()
                poshc2Db = f"/var/poshc2/{CURRENT_PROJECT}/PowershellC2.SQLite"
    except KeyError:
        logger.warning("ShellBot will continue without PoshC2")
        count += 1

    # Parse Metasploit config
    try:
        msfRpcHost = config["msf"]["host"]
        msfRpcPort = config["msf"]["port"]
        msfRpcUser = config["msf"]["user"]
        msfRpcPass = config["msf"]["pass"]
        msf_rpc_get_temp_auth_token()
    except KeyError:
        logger.warning(
            "ShellBot will continue without Metasploit because configuration was not provided."
        )
        count += 1

    # Parse Covenant config
    try:
        covHost = config["covenant"]["host"]
        covPort = config["covenant"]["port"]
        covUser = config["covenant"]["user"]
        covPass = config["covenant"]["pass"]
        covApiToken = cov_api_auth(covUser, covPass)
    except KeyError:
        logger.warning(
            "ShellBot will continue without Covenant because configuration was not provided"
        )
        count += 1

    if count == 4:
        logger.critical("No valid C2 configurations found. Exiting")
        exit(1)


def check_empire_agents(db):
    # Check for new Empire agents

    agents = db_query(db)

    if args.verbose:
        logger.debug("{}".format(agents))
        logger.info("Currently checked in agents:")
        for a in agents:
            logger.info(
                "Session ID: {0}\t Checkin Time: {1}".format(
                    a, agents[a]["checkin_time"]
                )
            )
    for a in agents:
        checkin = datetime.datetime.strptime(
            agents[a]["checkin_time"], "%Y-%m-%d %H:%M:%S"
        )
        if a not in knownAgents["empire"]:
            knownAgents["empire"].append(a)
            if checkin > runTime:
                if (
                    discordHook is not None
                    and discordHook != ""
                    and discordHook != "https://discord.com/gg/<randomstuff>"
                ):
                    msg = "Agent ID: {0}\nCheckin Time: {1}".format(
                        agents[a]["session_id"], agents[a]["checkin_time"]
                    )
                    send_new_agent_message_discord("Empire", msg)
                else:
                    if args.verbose:
                        logger.warning("Discord hook not provided, skipping")
                if (
                    slackHook is not None
                    and slackHook != ""
                    and slackHook != "https://hooks.slack.com/services/<randomstuff>"
                ):
                    msg = "Agent ID: {0}\nCheckin Time: {1}".format(
                        agents[a]["session_id"], agents[a]["checkin_time"]
                    )
                    send_new_agent_message_slack("Empire", msg)
                else:
                    if args.verbose:
                        logger.warning("Slack hook not provided, skipping")
                if (
                    teamsHook is not None
                    and teamsHook != ""
                    and teamsHook != "https://outlook.office.com/webhook/<randomstuff>"
                ):
                    send_new_agent_message_teams("Empire", agents[a])
                else:
                    if args.verbose:
                        logger.warning("Teams hook not provided, skipping")


def check_poshc2_agents(db):
    # Check for new PoshC2 Agents

    agents = poshc2_db_query(db)

    if args.verbose:
        logger.debug("Currently checked in agents:")
        for a in agents:
            logger.debug(
                "Implant ID: {0}\t First Seen: {1}".format(
                    agents[a]["ImplantID"], agents[a]["FirstSeen"]
                )
            )
    send_count = 0
    for a in agents:
        checkin = datetime.datetime.strptime(
            agents[a]["FirstSeen"], "%Y-%m-%d %H:%M:%S"
        )
        if a not in knownAgents["poshc2"]:
            knownAgents["poshc2"].append(a)
            msg = agents[a]
            if checkin > runTime:
                if (
                    discordHook is not None
                    and discordHook != "https://discord.com/gg/<randomstuff>"
                ):
                    print("Sending to discord")
                    send_new_agent_message_discord("poshc2", msg)
                    send_count += 1
                else:
                    if args.verbose:
                        logger.warning("Discord hook not provided, skipping")

                if (
                    slackHook is not None
                    and slackHook != "https://hooks.slack.com/services/<randomstuff>"
                ):
                    send_new_agent_message_slack("poshc2", msg)
                else:
                    if args.verbose:
                        logger.warning("Slack hook not provided, skipping")

                if (
                    teamsHook is not None
                    and teamsHook != "https://outlook.office.com/webhook/<randomstuff>"
                ):
                    send_new_agent_message_teams("poshc2", msg)
                else:
                    if args.verbose:
                        logger.warning("Teams hook not provided, skipping")


def check_msf_agents():
    """Check to see if there are any new meterpreter sessions"""
    if args.verbose:
        logger.info("Checking for new Meterpreter agents")
    msf_rpc_get_temp_auth_token()
    if msfRpcToken is not None:
        sessions_result = msf_rpc_get_session_list()
        if sessions_result is not None:
            for s in sessions_result:
                if args.verbose:
                    logger.debug("Agent Information:\n{}".format(sessions_result[s]))
                if sessions_result[s]["uuid"] not in knownAgents["msf"]:
                    knownAgents["msf"].append(sessions_result[s]["uuid"])
                    msg = "Agent: {0}\nInfo: {1}\nUsername: {2}\nTunnel Local: {3}\nTunnel Peer: {4}\nSession Port: {5}\nExploit: {6}\nPayload: {7}\nPlatform: {8}\nRoutes: {9}".format(
                        sessions_result[s]["uuid"],
                        sessions_result[s]["info"],
                        sessions_result[s]["username"],
                        sessions_result[s]["tunnel_local"],
                        sessions_result[s]["tunnel_peer"],
                        sessions_result[s]["session_port"],
                        sessions_result[s]["via_exploit"],
                        sessions_result[s]["via_payload"],
                        sessions_result[s]["platform"],
                        sessions_result[s]["routes"],
                    )
                    if (
                        discordHook is not None
                        and discordHook != ""
                        and discordHook != "https://discord.com/gg/<randomstuff>"
                    ):
                        send_new_agent_message_discord("Meterpreter", msg)
                    else:
                        if args.verbose:
                            logger.warning("Discord hook not provided, skipping")
                    if (
                        slackHook is not None
                        and slackHook != ""
                        and slackHook
                        != "https://hooks.slack.com/services/<randomstuff>"
                    ):
                        send_new_agent_message_slack("Meterpreter", msg)
                    else:
                        if args.verbose:
                            logger.warning("Slack hook not provided, skipping")
                    if (
                        teamsHook is not None
                        and teamsHook != ""
                        and teamsHook
                        != "https://outlook.office.com/webhook/<randomstuff>"
                    ):
                        send_new_agent_message_teams("Meterpreter", sessions_result[s])
                    else:
                        if args.verbose:
                            logger.warning("Teams hook not provided, skipping")


def check_covenant_agents():
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
    url = f"https://{covHost}:{covPort}/api/grunts"
    req_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {covApiToken}",
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
                        active_time = datetime.datetime.strptime(
                            grunt["activationTime"].split(".")[0], "%Y-%m-%dT%H:%M:%S"
                        )
                        # Convert activation time to be timezone aware (UTC) and convert to local timezone
                        active_time_local = active_time.replace(
                            tzinfo=datetime.timezone.utc
                        ).astimezone()

                        if (
                            grunt["guid"] not in knownAgents["covenant"]
                            and active_time_local > runTime.astimezone()
                        ):
                            knownAgents["covenant"].append(grunt["guid"])
                            logger.info(
                                f"Covenant Grunt Check: New grunt checked in! GUID: {grunt['guid']}"
                            )
                            # msg = f"Grunt Name: {grunt['name']}\nCheckin Time: {active_time_local}\n"
                            # msg += f"System Info --\n"
                            # msg += f"\tHostname: {grunt['hostname']}\n\tIP Addr: {grunt['ipAddress']}\n"
                            # msg += f"\tDomain\\User: {grunt['userDomainName']}\\{grunt['userName']}\n"
                            # msg += f"\tOS Info: {grunt['operatingSystem']}"
                            msg = grunt
                            logger.info(
                                f"Covenant Grunt Check: New Grunt details:\n{msg}"
                            )

                            if (
                                slackHook is not None
                                and slackHook != ""
                                and slackHook
                                != "https://hooks.slack.com/services/<randomstuff>"
                            ):
                                send_new_agent_message_slack("covenant", msg)
                            else:
                                if args.verbose:
                                    logger.warning("Slack hook not provided, skipping")
                            if (
                                discordHook is not None
                                and discordHook != ""
                                and discordHook
                                != "https://discord.com/gg/<randomstuff>"
                            ):
                                send_new_agent_message_discord("covenant", msg)
                            else:
                                if args.verbose:
                                    logger.warning(
                                        "Discord hook not provided, skipping"
                                    )
                            continue
                        else:
                            logger.debug(
                                f"Covenant Grunt Check: Grunt ({grunt['guid']}) is already known about."
                            )
                            continue
                else:
                    logger.debug("Covenant Grunt Check: No new grunts")
                    return
            else:
                logger.error(
                    "Covenant Grunt Check Failed: Unexpected response content-type"
                )
        else:
            logger.error("Covenant  Grunt Check Failed: Unexpected server response")


def receiveSignal(signalNumber, frame):
    print(f"Received: {signalNumber}")
    raise SystemExit("Exiting")


def main():
    signal.signal(signal.SIGTERM, receiveSignal)
    # header = '"Content-Type: application/json"'
    # useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    ascii_art()
    host_ip, host_location, host_name = get_IP()
    try:
        config = parse_config()
        if (
            (config["empire"]["db"])
            or (config["msf"]["pass"])
            or (config["cov"]["token"])
            or (["poshc2"]["db"])
        ):
            if discordHook:
                logger.info("Posting to Discord")
                post_msg_discord("Hello", "Started", "65323")
            if slackHook:
                logger.info("Posting to Slack")
                post_msg_slack("Hello", "Started")
            logger.info(
                "ShellBot started on {0}, {1}".format(host_name, host_ip, host_location)
            )

            while True:
                signal.signal(signal.SIGTERM, receiveSignal)
                if empireDb:
                    check_empire_agents(empireDb)
                if msfRpcToken:
                    check_msf_agents()
                if covApiToken:
                    check_covenant_agents()
                if poshc2Db:
                    check_poshc2_agents(poshc2Db)
                if args.verbose:
                    logger.debug(
                        "Sleeping for {0} seconds at {1}".format(
                            sleepTime, datetime.datetime.now()
                        )
                    )
                time.sleep(sleepTime)
        else:
            logger.warning(
                "Unable to locate or communicate with any C2 servers. Quitting"
            )
            sys.exit(1)
    except NameError:
        logger.critical("No C2 frameworks integrated. Quitting...")
    except KeyboardInterrupt:
        logger.critical("User Interrupt! Quitting....")
        if discordHook is not None:
            logger.info("Posting to Discord")
            post_msg_discord("Good-Bye", "Exited", "16711680")
        if slackHook is not None:
            logger.info("Posting to Slack")
            post_msg_slack("Good-Bye", "Exited")
    except:
        if discordHook is not None:
            logger.info("Posting to Discord")
            post_msg_discord("Good-Bye", "Exited", "16711680")
        if slackHook is not None:
            logger.info("Posting to Slack")
            post_msg_slack("Good-Bye", "Exited")
        logger.info(
            "Please report this error to "
            + __maintainer__
            + " by email at: "
            + __email__
        )
        raise


if __name__ == "__main__":
    main()
