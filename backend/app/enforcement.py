"""Safe edge-firewall integration contract; no network rules are applied here."""
class LoggingOnlyFirewall:
    def add_deny_rule(self, ip_address: str, reason: str) -> None:
        import logging
        logging.getLogger("ary.cybershield.firewall").warning("BLOCK_REQUEST_RECORDED ip=%s reason=%s",ip_address,reason)
    def remove_deny_rule(self, ip_address: str) -> None:
        import logging
        logging.getLogger("ary.cybershield.firewall").info("UNBLOCK_REQUEST_RECORDED ip=%s",ip_address)
