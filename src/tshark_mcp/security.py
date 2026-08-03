"""Protocol allowlist and input-validation helpers.

The allowlist is the primary defense against display-filter injection: a
protocol token is only emitted into a filter after passing
:func:`is_allowed_protocol`. The current set is also surfaced to MCP clients
via the tool's inputSchema (``Literal`` enums where applicable).
"""

from __future__ import annotations

#: Protocols accepted as display-filter tokens. Add entries here when a new
#: dissector must be analyzable; case-insensitive lookup.
PROTOCOL_ALLOWLIST: frozenset[str] = frozenset(
    {
        # link / network
        "arp", "icmp", "icmpv6", "ip", "ipv6", "eth",
        # transport
        "tcp", "udp",
        # common application-layer
        "http", "http2", "dns", "tls", "ssl", "ftp", "ftps",
        "mqtt", "coap", "ssh", "telnet", "smtp", "pop", "imap",
        "ntp", "dhcp", "dhcpv6", "snmp", "rtsp", "sip", "sdp",
        "ldap", "ldaps", "websocket",
        # reassembly / payload layers seen in download/fota pcaps in this repo
        "tcp.segments", "data", "data-text-lines",
    }
)


def is_allowed_protocol(token: str) -> bool:
    """Case-insensitive membership test against :data:`PROTOCOL_ALLOWLIST`."""
    return token.lower() in PROTOCOL_ALLOWLIST
