import logging
logger=logging.getLogger("ary.cybershield")
def notify_security_event(event):
    if event.severity == "high":
        logger.warning("HIGH_SECURITY_EVENT ip=%s category=%s target=%s event_id=%s", event.source_ip,event.category,event.target,event.id)
