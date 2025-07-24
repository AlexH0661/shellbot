def check_agents(db_path):
    """Query sqlite database"""

    agents = {}

    try:
        connection = sqlite3.connect(db_path)
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
        logger.warning("Error connecting to the database at {}".format(dbPath))
        print(e)

    return agents