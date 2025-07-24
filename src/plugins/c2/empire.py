# Configuration variables
empireDb = None

def check_agents(db_path):
    #Check for new Empire agents

    agents = db_query(db_path)

    if args.verbose:
        logger.debug("{}".format(agents))
        logger.info("Currently checked in agents:")
        for a in agents:
            logger.info("Session ID: {0}\t Checkin Time: {1}".format(a, agents[a]['checkin_time']))
    for a in agents:
        checkin = datetime.datetime.strptime(agents[a]['checkin_time'], "%Y-%m-%d %H:%M:%S")
        if a not in knownAgents["empire"]:
            knownAgents["empire"].append(a)
            if checkin > runTime:
                if discordHook is not None and discordHook != "" and \
                        discordHook != "https://discord.com/gg/<randomstuff>":
                    msg = "Agent ID: {0}\nCheckin Time: {1}".format(agents[a]['session_id'], agents[a]['checkin_time'])
                    send_new_agent_message_discord("Empire", msg)
                else:
                    if args.verbose:
                        logger.warning("Discord hook not provided, skipping")
                if slackHook is not None and slackHook != "" and \
                        slackHook != "https://hooks.slack.com/services/<randomstuff>":
                    msg = "Agent ID: {0}\nCheckin Time: {1}".format(agents[a]['session_id'], agents[a]['checkin_time'])
                    send_new_agent_message_slack("Empire", msg)
                else:
                    if args.verbose:
                        logger.warning("Slack hook not provided, skipping")
                if teamsHook is not None and teamsHook != "" and \
                        teamsHook != "https://outlook.office.com/webhook/<randomstuff>":
                    send_new_agent_message_teams("Empire", agents[a])
                else:
                    if args.verbose:
                        logger.warning("Teams hook not provided, skipping")