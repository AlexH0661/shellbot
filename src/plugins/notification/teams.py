# Configuration variables
teamsHook = None

def post_msg(msg, status, colour):
    if args.verbose:
        logger.debug("New Microsoft Teams agent message agent: {0}, payload: {1}".format(agentType, payload))

    data = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "{0}".format(msg),
        "title": "ShellBot {} on ".format(status) + host_ip,
        "themeColor": "{0}".format(colour),
    }

    data_msg = parse.urlencode(data).encode()
    req =  request.Request(teamsHook, data=data_msg, headers={'content-type': 'application/json'})
    response = request.urlopen(req)
    logger.debug('Server response: {}'.format(response.getcode()))

def send_new_agent_message(agentType, payload):
    if args.verbose:
        logger.debug("New Microsoft Teams agent message agent: {0}, payload: {1}".format(agentType, payload))

    data = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "[+] New {0} agent check in".format(agentType),
        "title": "[+] New {1} agent check in".format(agentType),
        "themeColor": "FF1000",
        "sections": [{"text": "I smell pwnage in the air..."}, {"facts": [{"name": "Agent Type", "value": agentType}]}]
    }

    for p in payload:
        data["sections"][1]["facts"].append({"name": p, "value": payload[p]})

    data_msg = parse.urlencode(data).encode()
    req =  request.Request(teamsHook, data=data_msg, headers={'content-type': 'application/json'})
    response = request.urlopen(req)

    if args.verbose:
        logger.debug(response.text)
        logger.debug("{}".format(response.getcode()))
        logger.debug("{}".format(data))
    if response.getcode() == 200:
        print(check_in + "New {0} agent check in successfully posted to Microsoft Teams".format(agentType))
        if agentType == "Empire":
            logger.info("Agent ID: {0}, Checkin Time: {1}".format(payload.get("session_id"), payload.get("checkin_time")))
        elif agentType == "Meterpreter":
            logger.info("Meterpreter UUID: {0}, Info: {1}".format(payload.get("uuid"), payload.get("info")))
    else:
        logger.warning("Message not posted to Microsoft Teams. HTTP Status Code: {}".format(response.getcode()))