#! /usr/bin/env python

__author__ = 'Russel Van Tuyl'
__maintainer__ = "Huss"
__DiscordChannel__ = "https://discord.gg/jxtfgep"
__version__ = "2.8.1"

import sqlite3
import datetime
import requests
import time
import ConfigParser
import msgpack
import sys
import os
import argparse
import socket
import subprocess
import json

#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m[-]\033[0m"
warn = "\033[0;0;31m[!]\033[0m"
info = "\033[0;0;36m[i]\033[0m"
question = "\033[0;0;37m[?]\033[0m"
debug = "\033[0;0;31m[DEBUG]\033[0m"

ssb_root = os.path.dirname(os.path.realpath(__file__))
runTime = datetime.datetime.now()
sleepTime = 30
DiscordHook = 'https://discordapp.com/api/webhooks/555880251524251649/Q2MhrMSqJ0o-QheJek2jQoU_wnPigWdC4crdlsg7ONAwcbzRTamljjIUYA0apRu0WGzu'
botName = None
channel = None
empireDb = None
msfRpcHost = "127.0.0.1"
msfRpcPort = "55553"
msfRpcUser = "msf"
msfRpcPass = "test"
msfRpcToken = None
knownAgents = {"empire": [], "msf": []}

DEBUG = False
VERBOSE = False

host_name = ''
host_ip = ''

os.system('clear')
ascii_art = """
  ____   _            _  _  ____          _   
 / ___| | |__    ___ | || || __ )   ___  | |_ 
 \___ \ | '_ \  / _ \| || ||  _ \  / _ \ | __|
  ___) || | | ||  __/| || || |_) || (_) || |_ 
 |____/ |_| |_| \___||_||_||____/  \___/  \__|
                                              
"""
print ascii_art
print "Created by: Russel Van Tuyl"
print "Maintained by: Huss"
print "Version 2.8.1"
print ""
print info + "Starting up..."

msfremote = subprocess.Popen("ruby /usr/share/metasploit-framework/msfrpcd -U msf -P test -S false", shell=True)

msfremote
print info + "Starting MSFRPCD"

while msfremote.poll() != 0:
    print info + "MSFRPCD not started. Sleeping 10s..."
    time.sleep(10)
    if msfremote.poll() == 0:
        break

# allow time to establish a connection
time.sleep(5)

def get_IP(): 
    try:
        global host_name
        global host_ip 
        host_name = str(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0] 
        # print("Hostname :  ",host_name) 
        # print("IP : ",host_ip) 
    except: 
        print warn + "Unable to get Hostname and IP" 
get_IP()

def db_query(dbPath):
    """Query sqlite database"""

    agents = {}

    try:
        connection = sqlite3.connect(dbPath)
        rs = connection.execute("SELECT session_id, checkin_time, name, external_ip, internal_ip, username, hostname, "
                                "os_details, high_integrity, process_name, process_id FROM agents;")

        for r in rs:
            agents[r[0]] = {'checkin_time': r[1],
                            'session_id': r[0],
                            'name': r[2],
                            'external_ip': r[3],
                            "internal_ip": r[4],
                            "username": r[5],
                            "hostname": r[6],
                            "os_details": r[7],
                            "high_integrity": str(r[8]),
                            "process_name": r[9],
                            "process_id": r[10]
                            }

        connection.close()
    except sqlite3.OperationalError as e:
        print warn + "Error connecting to the database at %s" % dbPath
        print e

    return agents


def msf_rpc_request(payload):
    """Make HTTP POST Request to MSF RPC Interface"""

    url = "http://" + msfRpcHost + ":" + msfRpcPort + "/api/1.1"
    headers = {'content-type': 'binary/message-pack'}
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False)
        return response
    except requests.exceptions.ConnectionError:
        print warn + "ShellBot will continue without Metasploit because it was unable to communicate with the RPC"\
                     " server at %s" % url
        print "\t" + info + "try 'load msgrpc` in your currently running Metasploit Instance"
        print "\t" + info + "Visit https://help.rapid7.com/metasploit/Content/api-rpc/getting-started-api.html for " \
                            "additional information"
        return None


def msf_rpc_get_temp_auth_token():
    """Get a temporary authentication token from the Metasploit RPC Server"""

    global msfRpcToken

    payload = msgpack.packb(["auth.login", msfRpcUser, msfRpcPass])
    response = msf_rpc_request(payload)

    if response is not None:
        if DEBUG:
            print debug + "MSF RPC auth.login response:\n\tHTTP Status Code: %s" % response.status_code
            if response.headers['Content-Type'] == "binary/message-pack":
                msf_rpc_message = msgpack.unpackb(response.content, use_list=False)
                print "\t" + debug + "MSF RPC Server Response: %s" % msf_rpc_message
                if 'error' in msf_rpc_message.keys():
                    print debug + "MSF RPC Error: %s" % msf_rpc_message['error_message']
            else:
                print "\t" + debug + "HTTP Server Response: %s" % response.content
        if response.status_code == 200:
            result = msgpack.unpackb(response.content, use_list=False)
            if 'error' in result.keys():
                print warn + "MSF RPC Error: %s" % result['error_message']
                print warn + "Quitting"
                sys.exit()
            elif 'token' in result.keys():
                msfRpcToken = result['token']


def msf_rpc_get_session_list():
    """Get a list of Metasploit sessions"""

    payload = msgpack.packb(["session.list", msfRpcToken])
    response = msf_rpc_request(payload)
    if response is not None:
        result = msgpack.unpackb(response.content, use_list=False)

        if response.status_code == 200:
            return result
        else:
            return None
    else:
        return None


def send_new_agent_message_Discord(agentType, payload):
    """Send New Agent Message to Discord"""

    
    if DEBUG:
        print debug + "New Discord agent message agent: %s, payload: %s" % (agentType, payload)

    if agentType == "Metasploit":
    	data = {}
	data["tts"] = "true"
	data["avatar_url"] = "https://ih1.redbubble.net/image.65324534.3912/raf,750x1000,075,t,fafafa:ca443f4786.u5.jpg"
	data["content"] = "New Metasploit Session"
    	data["username"] = "ShellBot - " + host_name
    	data["embeds"] = []
        embed = {}
        embed["color"] = "1108193"
        embed["description"] = payload
        embed["title"] = "[+]New " + agentType + " agent checked in to " + host_ip
	data["embeds"].append(embed)
    elif agentType == "Empire":
    	data = {}
	data["avatar_url"] = "https://avatars2.githubusercontent.com/u/25492515?s=400&v=4"
	data["content"] = "New Empire Session"
    	data["username"] = "ShellBot - " + host_name
	data["tts"] = "true"
    	data["embeds"] = []
        embed = {}
        embed["color"] = "1108193"
        embed["description"] = payload
        embed["title"] = "[+]New " + agentType + " agent checked in to " + host_ip
	data["embeds"].append(embed)

    response = requests.post(DiscordHook, data=json.dumps(data), headers={"Content-Type": "multipart/form-data"})

    if DEBUG:
        print debug + "%s" % response.text
        print debug + "%d" % response.status_code
    if response.status_code == 204:
        print "\033[0;0;92m[+]\033[0mNew %s agent check in successfully posted to Discord" % agentType
        print "\t" + note + "%s" % payload.replace("\n", ", ")
    else:
        print warn + "Message not posted to Discord. HTTP Status Code: %s" % response.status_code

def parse_config(configFile):
    """Parse the ShellBot configuration file and update global variables"""

    global sleepTime
    global DiscordHook
    global botName
    global channel
    global empireDb
    global msfRpcHost
    global msfRpcPort
    global msfRpcUser
    global msfRpcPass
    global teamsHook

    if VERBOSE:
        print note + "Parsing config file at %s" % configFile

    c = ConfigParser.ConfigParser()
    c.read(configFile)

    if c.has_section("Discord"):
        if c.has_option("Discord", "DiscordHook"):
            DiscordHook = c.get("Discord", "DiscordHook")
        else:
            print warn + "Configuration file missing 'DiscordHook' parameter in 'Discord' section"
            sys.exit(1)
    else:
        print warn + "Missing 'Discord' section in configuration file"
        sys.exit(1)

    # This section can be missing, will use global variables instead
    if c.has_section("ShellBot"):
        if c.has_option("ShellBot", "sleepTime"):
            sleepTime = c.getint("ShellBot", "sleepTime")

    if c.has_section("empire"):
        if c.has_option("empire", "db"):
            e = c.get("empire", "db")
            if os.path.isfile(os.path.join(ssb_root, e)):
                empireDb = os.path.join(ssb_root, e)
            else:
                print warn + "ShellBot will continue without Empire because database was not found at %s" \
                             % os.path.join(ssb_root, e)
        else:
            print warn + "ShellBot will continue without Empire because database path not provided."
    else:
        print warn + "ShellBot will continue without Empire because configuration was not provided."

    if c.has_section("msf"):
        if c.has_option("msf", "msfRpcHost"):
            msfRpcHost = c.get("msf", "msfRpcHost")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "host was not provided"
        if c.has_option("msf", "msfRpcPort"):
            msfRpcPort = c.get("msf", "msfRpcPort")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "port was not provided"
        if c.has_option("msf", "msfRpcUser"):
            msfRpcUser = c.get("msf", "msfRpcUser")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "user was not provided"
        if c.has_option("msf", "msfRpcPass"):
            msfRpcPass = c.get("msf", "msfRpcPass")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "password was not provided"
    else:
        print warn + "ShellBot will continue without Metasploit because configuration was not provided."

    msf_rpc_get_temp_auth_token()


def check_empire_agents(db):
    """Check for new Empire agents"""

    global knownAgents

    agents = db_query(db)

    if DEBUG:
        print debug + "%s" % agents
    if VERBOSE:
        print info + "Currently checked in agents:"
        for a in agents:
            print "\t" + info + "Session ID: %s\t Checkin Time: %s" % (a, agents[a]['checkin_time'])
    for a in agents:
        checkin = datetime.datetime.strptime(agents[a]['checkin_time'], "%Y-%m-%d %H:%M:%S")
        if a not in knownAgents["empire"]:
            knownAgents["empire"].append(a)
            if checkin > runTime:
                if DiscordHook is not None and DiscordHook != "" and \
                        DiscordHook != "https://hooks.Discord.com/services/<randomstuff>":
                    msg = "Agent ID: %s\nCheckin Time: %s" % (agents[a]['session_id'], agents[a]['checkin_time'])
                    send_new_agent_message_Discord("Empire", msg)
                else:
                    if VERBOSE:
                        print note + "Discord hook not provided, skipping"
def check_msf_agents():
    """Check to see if there are any new Metasploit sessions"""
    if VERBOSE:
        print info + "Checking for new Metasploit agents"
    msf_rpc_get_temp_auth_token()
    if msfRpcToken is not None:
        sessions_result = msf_rpc_get_session_list()
        if sessions_result is not None:
            for s in sessions_result:
                if DEBUG:
                    print debug + "Agent Information:\n%s" % sessions_result[s]
                if sessions_result[s]['uuid'] not in knownAgents['msf']:
                    knownAgents['msf'].append(sessions_result[s]['uuid'])
                    msg = "Agent: %s\nInfo: %s\nType: %s\nTunnel Local: %s\nTunnel Peer: %s\nExploit: %s\nPayload: %s\n" % (sessions_result[s]['uuid'],
                                                                               sessions_result[s]['info'],
                                                                               sessions_result[s]['type'],
                                                                               sessions_result[s]['tunnel_local'],
                                                                               sessions_result[s]['tunnel_peer'],
                                                                               sessions_result[s]['via_exploit'],
                                                                               sessions_result[s]['via_payload'])
                    if DiscordHook is not None and DiscordHook != "" and \
                            DiscordHook != "https://hooks.Discord.com/services/<randomstuff>":
                        send_new_agent_message_Discord("Metasploit", msg)
                    else:
                        if VERBOSE:
                            print note + "Discord hook not provided, skipping"
if __name__ == '__main__':

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output to console")
        parser.add_argument('-v', action='store_true', default=False, help="Enable verbose output to console")
        args = parser.parse_args()
        VERBOSE = args.v
        DEBUG = args.debug

        conf = os.path.join(ssb_root, "shellbot.conf")
        parse_config(conf)

        if (empireDb is not None) or (msfRpcToken is not None):
	    data = {}
	    data["tts"] = "true"
	    data["username"] = "ShellBot - " + host_name
	    data["content"] = "Hello!"
    	    data["embeds"] = []
            embed = {}
            embed["color"] = "1110528"
            embed["title"] = "ShellBot Started on " + host_ip
	    data["embeds"].append(embed)
            msg_response = requests.post(DiscordHook, data=json.dumps(data), headers={"Content-Type": "multipart/form-data"})
            print info + "ShellBot started on {0}, {1}".format(host_name, host_ip)
            if os.system('systemctl is-active apache2 -q') == 0:
                print info + "Apache2 is running"
            else:
                print info + "Starting Apache2"
                os.system('systemctl start apache2 -q')
            if os.system('systemctl is-active postgresql -q') == 0:
                print info + "Postgresql is running"
                print info + "Starting Armitage"
                #subprocess.Popen("armitage")
            else:
                print info + "Starting postgresql"
                os.system('systemctl start postgresql -q')
                #subprocess.Popen("armitage")
            while True:
                if empireDb is not None:
                    check_empire_agents(empireDb)
                if msfRpcToken is not None:
                    check_msf_agents()
                if VERBOSE:
                    print info + "Sleeping for %s seconds at %s" % (sleepTime, datetime.datetime.now())
                time.sleep(sleepTime)
        else:
            print warn + "Unable to locate or communicate with any C2 servers. Quitting"
            sys.exit(1)

    except KeyboardInterrupt:
        print "\n" + warn + "User Interrupt! Quitting...."
	data = {}
	data["tts"] = "true"
	data["username"] = "ShellBot - " + host_name
	data["content"] = "Good-Bye"
        data["embeds"] = []
        embed = {}
        embed["color"] = "16711680"
        embed["title"] = "ShellBot Exited on " + host_ip
	data["embeds"].append(embed)
        msg_response = requests.post(DiscordHook, data=json.dumps(data), headers={"Content-Type": "application/json"})
    except SystemExit:
        pass
    except:
        print "\n" + warn + "Please report this error to " + __maintainer__ + " via the Messages to Admins Discord Channel " + __DiscordChannel__
        raise
