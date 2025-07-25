import datetime
import logging

from utils import notifications

logger = logging.getLogger(__name__)

# Configuration variables
db = None
known_agents = []

def check_agents():
    agents = db_query(db)

    logger.debug("{}".format(agents))
    logger.debug("Currently checked in agents:")
    for a in agents:
        logger.debug("Session ID: {0}\t Checkin Time: {1}".format(a, agents[a]['checkin_time']))

    for a in agents:
        checkin = datetime.datetime.strptime(agents[a]['checkin_time'], "%Y-%m-%d %H:%M:%S")
        if a not in known_agents["empire"]:
            known_agents["empire"].append(a)
            msg = "Agent ID: {0}\nCheckin Time: {1}".format(agents[a]['session_id'], agents[a]['checkin_time'])
            notifications.send_new_agent_message("Empire", msg)
