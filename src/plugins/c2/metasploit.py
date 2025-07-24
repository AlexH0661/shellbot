import logging
import sys

import msgpack
from requests import request

from utils import notifications

logger = logging.getLogger(__name__)
known_agents = []

# Configuration variables
rpc_host = "127.0.0.1"
rpc_port = "55552"
rpc_user = "msf"
rpc_pass = None
rpc_token = None

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

def rpc_request(payload):
    #Make HTTP POST Request to MSF RPC Interface

    url = "http://" + rpc_host + ":" + rpc_port + "/api/1.1"
    try:
        req = request.Request(url, data=payload, headers={'content-type': 'binary/message-pack'})
        response = request.urlopen(req)
        return response

    except BaseException as e:
        logger.warning(e)
        logger.warning("ShellBot will continue without Metasploit because it was unable to communicate with the RPC server at {}".format(url))
        logger.info("try 'load msgrpc` in your currently running Metasploit Instance")
        logger.info("Visit https://help.rapid7.com/metasploit/Content/api-rpc/getting-started-api.html for additional information")
        return None


def rpc_get_temp_auth_token():
    #Get a temporary authentication token from the Metasploit RPC Server
    global VERBOSE
    global rpc_token

    payload = msgpack.packb(["auth.login", rpc_user, rpc_pass])
    response = rpc_request(payload)
    try:
        content = msgpack.unpackb(response.read())
        content = decode_dict(content)
    except BaseException as e:
        if str(e) == None:
            exit(1)
    if response is not None:
        if VERBOSE:
            logger.debug("MSF RPC auth.login response:\n\tHTTP Status Code: {}".format(response.getcode()))
            if response.headers['Content-Type'] == "binary/message-pack":
                msf_rpc_message = content
                logger.debug("MSF RPC Server Response: {}".format(msf_rpc_message))
                if 'error' in msf_rpc_message.keys():
                    logger.debug("MSF RPC Error: {}".format(msf_rpc_message['error_message']))
            else:
                logger.debug("HTTP Server Response: {}".format(content))
        if response.getcode() == 200:
            if 'error' in content.keys():
                logger.warning("MSF RPC Error: {}".format(content['error_message']))
                logger.warning("Quitting")
                sys.exit()
            elif 'token' in content.keys():
                msfRpcToken = content['token']

def rpc_get_session_list():
    payload = msgpack.packb(["session.list", rpc_token])
    response = rpc_request(payload)
    content = msgpack.unpackb(response.read())
    content = decode_dict(content)
    if response is not None:
        if response.getcode() == 200:
            return content
        else:
            return None
    else:
        return None

def check_agents():

    logger.debug("Checking for new Meterpreter agents")
    rpc_get_temp_auth_token()

    if rpc_token is not None:
        sessions_result = rpc_get_session_list()
        if sessions_result is not None:
            for s in sessions_result:
                if VERBOSE:
                    logger.debug("Agent Information:\n{}".format(sessions_result[s]))
                if sessions_result[s]['uuid'] not in known_agents:
                    known_agents.append(sessions_result[s]['uuid'])
                    msg = "Agent: {0}\nInfo: {1}\nUsername: {2}\nTunnel Local: {3}\nTunnel Peer: {4}\nSession Port: {5}\nExploit: {6}\nPayload: {7}\nPlatform: {8}\nRoutes: {9}".format(sessions_result[s]['uuid'], sessions_result[s]['info'], sessions_result[s]['username'], sessions_result[s]['tunnel_local'], sessions_result[s]['tunnel_peer'], sessions_result[s]['session_port'], sessions_result[s]['via_exploit'], sessions_result[s]['via_payload'], sessions_result[s]['platform'], sessions_result[s]['routes'])
                    notifications.send_new_agent_message_slack("Meterpreter", msg)