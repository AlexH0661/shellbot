import logging
import sqlite3

from utils import notifications

logger = logging.getLogger(__name__)

known_agents = []
db = None

def check_agents():
    try:
        connection = sqlite3.connect(db)
        cur = connection.cursor()
        res = cur.execute('SELECT id, last_seen, hostname, ip_address, user, domain, process_name, type FROM implants;')
        for r in res.fetchall():
            logger.debug(r)
            if r not in known_agents:
                known_agents.append(r)
                msg = "Implant ID: {0}\nCheckin Time: {1}".format(r["id"], r["last_seen"])
                notifications.send_new_agent_message("PoshC2", msg)
        connection.close()
    except sqlite3.OperationalError as e:
        logger.warning("Error connecting to the database at {}".format(db))
        print(e)

    return known_agents