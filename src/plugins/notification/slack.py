# Configuration variables
slackHook = None
slackChannel = None

def post_msg(msg, status=None):
    total_data = {}
    total_data["username"] = "ShellBot - {}".format(host_name)
    total_data["icon_emoji"] = ":shellbot:"
    total_data["text"] = msg
    total_data["blocks"] = []
    data = defaultdict(dict)
    data["type"] = "section"
    data["text"]["type"] = "mrkdwn"
    data["text"]["text"] = "{0}\r\n```ShellBot {1} on {2}```".format(msg, status, host_ip)
    total_data["blocks"].append(data)
    req =  request.Request(slackHook, data=bytes(json.dumps(total_data), 'UTF-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363')
    response = request.urlopen(req)
    logger.debug('Server response: {}'.format(response.getcode()))

def send_new_agent_message_slack(agentType, payload):
    # Send New Agent Message to Slack
    if args.verbose:
        logger.debug("New Slack agent message agent: {0}, payload: {1}".format(agentType, payload))
    text = "```[+] New {0} agent check in to {1}\n{2}```".format(agentType, host_ip, payload)
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

    logger.debug(total_data)
    req = request.Request(slackHook, data=bytes(json.dumps(total_data), 'UTF-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363')
    response = request.urlopen(req)

    if args.verbose:
        logger.debug("{}".format(response.read()))
        logger.debug("{}".format(response.getcode()))
    if response.getcode() == 200:
        print(check_in + "New {} agent check in successfully posted to Slack".format(agentType))
        logger.info("{}".format(payload.replace("\n", ", ")))
    else:
        logger.warning("Message not posted to Slack. HTTP Status Code: {0}".format(response.getcode()))