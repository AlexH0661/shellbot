# Configuration variables
discordHook = None

def post_msg(msg, status=None, colour='15776264'):
    data = {}
    data["tts"] = "true"
    data["username"] = "ShellBot - " + host_name
    data["avatar_url"] = "https://www.jing.fm/clipimg/full/12-125257_baby-sea-turtle-clipart-cute-easy-turtle-drawings.png"
    data["embeds"] = []
    embed = {}
    embed["color"] = colour
    embed["title"] = "ShellBot {} on ".format(status) + host_ip
    embed["description"] = '`' + msg + '`'
    data["embeds"].append(embed)
    req =  request.Request(discordHook, data=bytes(json.dumps(data), 'UTF-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363')
    response = request.urlopen(req)
    logger.debug('Server response: {}'.format(response.getcode()))

def send_new_agent_message(agentType, payload):
    data = {}
    embed = {}
    # Send New Agent Message to Discord
    if args.verbose:
        logger.debug("New Discord agent message agent: {0}, payload: {1}".format(agentType, payload))

    if agentType == "Meterpreter":
        data["tts"] = "true"
        data[
            "avatar_url"] = "https://ih1.redbubble.net/image.65324534.3912/raf,750x1000,075,t,fafafa:ca443f4786.u5.jpg"
        data["content"] = "New Metasploit Session"
        data["username"] = "ShellBot - " + host_name
        data["embeds"] = []
        embed["color"] = "1108193"
        embed["description"] = payload
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        data["embeds"].append(embed)

    elif agentType == "Empire":
        data["avatar_url"] = "https://avatars2.githubusercontent.com/u/25492515?s=400&v=4"
        data["content"] = "New Empire Session"
        data["username"] = "ShellBot - " + host_name
        data["tts"] = "true"
        data["embeds"] = {}
        embed["color"] = "1108193"
        embed["description"] = payload
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        data["embeds"].append(embed)

    elif agentType.lower() == "covenant":
        data["avatar_url"] = "https://raw.githubusercontent.com/wiki/cobbr/Covenant/covenant.png"
        data["content"] = "New Covenant Session"
        data["username"] = "ShellBot - " + host_name
        data["tts"] = "true"
        data["embeds"] = {}
        embed["color"] = "1108193"
        embed["description"] = payload
        embed["title"] = "[+] New " + agentType + " agent checked in to " + host_ip
        data["embeds"].append(embed)

    logger.debug(data)
    req = request.Request(discordHook, data=bytes(json.dumps(data), 'UTF-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363')
    response = request.urlopen(req)
    if args.verbose:
        logger.debug("{}".format(response.read().decode()))
        logger.debug("{}".format(response.getcode()))
    if response.getcode() == 204 or response.getcode() == 200:
        print(check_in + "New {} agent check in successfully posted to Discord".format(agentType))
        logger.info("{}".format(payload.replace("\n", ", ")))
    else:
        logger.warning("Message not posted to Discord. HTTP Status Code: {}".format(response.getcode()))