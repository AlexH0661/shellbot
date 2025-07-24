"""
The purpose of this library is to provide a common interface for
sending notifications
"""

# TODO add a method to send notifications to all enabled notification plugins

def send_agent_notification(c2_framework, msg):
    print("C2: %s\n Message: %s" % c2_framework, msg)