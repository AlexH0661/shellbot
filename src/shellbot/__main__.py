#!/usr/bin/env python3

__author__ = 'Russel Van Tuyl'
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__updated__ = "AlexH0661"
__version__ = "2.0.0"

import argparse
import datetime
import logging
import os
import socket
import time

import yaml

from plugins.c2 import empire, metasploit, covenant

try:
    import msgpack
except BaseException as e:
    print(e)

# TODO dynamically import plugins
from plugins.notification import slack, discord, teams

# Default configuration values
VERBOSE = False
SLACK_ENABLED = False
DISCORD_ENABLED = False
TEAMS_ENABLED = False
METASPLOIT_ENABLED = False
EMPIRE_ENABLED = False
COVENANT_ENABLED = False
POSH_ENABLED = False
WORKING_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
START_TIME = datetime.datetime.now()
SLEEP_TIME = 60
LOG_TO_FILE = False
KNOWN_AGENTS = {"empire": [], "msf": [], "covenant": []}
HOST_NAME = "localhost"
HOST_IP = "127.0.0.1"
CONFIG = {}

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', default=False,
                    help="Enable verbose/debug output to console")
args = parser.parse_args()

cur_datetime = datetime.datetime.now()
formatted_datetime = cur_datetime.strftime("%Y-%m-%d-%H%M%S")
cur_dir = os.getcwd()
os.makedirs('{}/logs'.format(cur_dir), exist_ok=True)

# Logging configuration
if LOG_TO_FILE:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(name)s / %(levelname)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='{0}/logs/{1}.log'.format(cur_dir, formatted_datetime),
        filemode='w'
    )
console = logging.StreamHandler()
if args.verbose:
    console.setLevel(logging.DEBUG)
    VERBOSE = True
else:
    console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
logger = logging.getLogger('')

# Colours
note = "\033[0;0;33m[-]\033[0m "
warn = "\033[0;0;31m[!]\033[0m "
info = "\033[0;0;36m[i]\033[0m "
question = "\033[0;0;37m[?]\033[0m "
debug = "\033[0;0;31m[DEBUG]\033[0m "
check_in = "\033[0;0;92m[+]\033[0m "

def ascii_art():
    art = "\033[0;0;36m"
    art += r"""
ShellBot
"""
    art += "\033[0m"
    art += """
Author: {0}
Maintainer: {1}
Email: {2}
Last Updated By: {3}
Version: {4}

""".format(__author__, __maintainer__, __email__, __updated__, __version__)
    print(art)


def get_IP():
    try:
        global HOST_NAME
        global HOST_IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        HOST_NAME = socket.gethostname()
        HOST_IP = s.getsockname()[0]
        logger.debug(HOST_NAME)
        logger.debug(HOST_IP)
    except BaseException as e:
        logger.warning(e)

def parse_config():
    #Parse the ShellBot configuration file and update global variables
    global SLACK_ENABLED
    global DISCORD_ENABLED
    global TEAMS_ENABLED
    global METASPLOIT_ENABLED
    global EMPIRE_ENABLED
    global COVENANT_ENABLED
    global POSH_ENABLED
    global SLEEP_TIME
    global empireDb

    with open("shellbot.yaml") as fp:
        config = yaml.safe_load(fp)
    count = 0

    # If no notification sources are defined, we log to stdout and file system
    if "slack" in config:
        if config["slack"]["slackHook"] != None and config["slack"][
            "slackHook"] != "https://hooks.slack.com/services/<randomstuff>":
            slack.slackHook = config["slack"]["slackHook"]
        else:
            logger.warning("Slack Web Hook was not provided")
            count += 1
        if config["slack"]["channel"]:
            slack.slackChannel = config["slack"]["channel"]
        else:
            logger.warning("Configuration file missing 'channel' parameter in 'slack' section")

        SLACK_ENABLED = True

    if "discord" in config:
        if config["discord"]["discordHook"] != None and config["discord"][
            "discordHook"] != "https://discord.com/gg/<randomstuff>":
            discord.discordHook = config["discord"]["discordHook"]
            DISCORD_ENABLED = True
        else:
            logger.warning("Discord Web Hook was not provided")
            count += 1

    if "teams" in config:
        if config["teams"]["teamsHook"]:
            if config["teams"]["teamsHook"] != "https://outlook.office.com/webhook/<randomstuff>":
                teams.teamsHook = config["teams"]["teamsHook"]
                TEAMS_ENABLED = True
            else:
                logger.warning("Microsoft Teams Web Hook was not provided")
                count += 1
    if count == 3:
        logger.critical("No notification source were provided. Logging to stdout")

    # This configuration section is optional
    if "shellbot" in config:
        if "sleep-time" in config["shellbot"]:
            SLEEP_TIME = int(config["shellbot"]["sleep-time"])

    # At least one C2 framework must be configured
    if "empire" in config:
        if "db" in config["empire"]:
            e = config["empire"]["db"]
            if os.path.isfile(os.path.join(WORKING_DIRECTORY, e)):
                empire.empireDb = os.path.join(WORKING_DIRECTORY, e)
                EMPIRE_ENABLED = True
            else:
                logger.warning("ShellBot will continue without Empire because database was not found at {}".format(
                    os.path.join(WORKING_DIRECTORY, e)))
        else:
            logger.warning("ShellBot will continue without Empire because database path not provided.")
    else:
        logger.warning("ShellBot will continue without Empire because configuration was not provided.")

    msf_count = 0
    if "msf" in config:
        if config["msf"]["rpc_host"]:
            metasploit.rpc_host = config["msf"]["rpc_host"]
        else:
            logger.warning("ShellBot will continue without Metasploit Framework because the host was not provided")
            msf_count += 1
        if config["msf"]["rpc_port"]:
            metasploit.rpc_port = config["msf"]["rpc_port"]
        else:
            logger.warning("ShellBot will continue without Metasploit Framework because the port was not provided")
            msf_count += 1
        if config["msf"]["rpc_user"]:
            metasploit.rpc_user = config["msf"]["rpc_user"]
        else:
            logger.warning("ShellBot will continue without Metasploit Framework because the user was not provided")
            msf_count += 1
        if config["msf"]["rpc_pass"] != None and config["msf"]["rpc_pass"] != "<password>":
            metasploit.rpc_pass = config["msf"]["rpc_pass"]
        else:
            logger.warning("ShellBot will continue without Metasploit Framework because the password was not provided")
            msf_count += 1
        if msf_count == 0:
            metasploit.rpc_get_temp_auth_token()
            METASPLOIT_ENABLED = True
    else:
        logger.warning("ShellBot will continue without Metasploit because configuration was not provided.")

    cov_count = 0
    if "covenant" in config:
        if config["covenant"]["host"]:
            covenant.host = config["covenant"]["host"]
        else:
            logger.warning("ShellBot will continue without Covenant because the host was not provided")
            cov_count += 1
        if config["covenant"]["port"]:
            covenant.port = config["covenant"]["port"]
        else:
            logger.warning("ShellBot will continue without Covenant because the port was not provided")
            cov_count += 1
        if config["covenant"]["user"] != "":
            covenant.user = config["covenant"]["user"]
        else:
            logger.warning("ShellBot will continue without Covenant because the user was not provided")
            cov_count += 1
        if config["covenant"]["pass"]:
            covenant.password = config["covenant"]["pass"]
        else:
            logger.warning("ShellBot will continue without Covenant because the password was not provided")
            cov_count += 1
        if cov_count == 0:
            covenant.api_token = covenant.api_auth(covenant.user, covenant.password)
            COVENANT_ENABLED = True
    else:
        logger.warning("ShellBot will continue without Covenant because configuration was not provided")

    if not METASPLOIT_ENABLED and not COVENANT_ENABLED and not EMPIRE_ENABLED:
        logger.critical('No valid C2 configurations found. Exiting')
        exit(1)


def main():
    parse_config()
    header = '"Content-Type: application/json"'
    useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"
    ascii_art()
    get_IP()
    try:
        if DISCORD_ENABLED:
            logger.info("Posting to Discord")
            discord.post_msg('Hello', 'Started', '65323')

        if SLACK_ENABLED:
            logger.info("Posting to Slack")
            slack.post_msg('Hello', 'Started')

        if TEAMS_ENABLED:
            logger.info("Posting to Teams")
            teams.post_msg('Hello', 'Started', '65323')

        logger.info("ShellBot started on {0}, {1}".format(host_name, host_ip))

        while True:
            if EMPIRE_ENABLED:
                empire.check_agents(empireDb)
            if METASPLOIT_ENABLED:
                metasploit.check_agents()
            if COVENANT_ENABLED:
                covenant.check_agents()
            if args.verbose:
                logger.debug("Sleeping for {0} seconds at {1}".format(sleepTime, datetime.datetime.now()))
            time.sleep(sleepTime)

    except KeyboardInterrupt:
        logger.critical("User Interrupt! Quitting....")

        if DISCORD_ENABLED:
            logger.debug("Posting to Discord")
            discord.post_msg('Good-Bye', 'Exited', '16711680')

        if SLACK_ENABLED:
            logger.debug("Posting to Slack")
            slack.post_msg('Good-Bye', 'Exited')

        if TEAMS_ENABLED:
            logger.debug("Posting to Teams")
            teams.post_msg('Good-Bye', 'Exited', '16711680')

    except SystemExit:
        pass
    except:
        logger.info("Please report this error to " + __maintainer__ + " by email at: " + __email__)
        raise


if __name__ == '__main__':
    main()
