# Legacy Netgear web collection

Use `--device-type netgear_web` for the legacy GS724TS web interface when SSH is
unavailable. This collector was exercised against GS724TS firmware V5.0.0.23.
GS724Tv4 and UniFi web interfaces are not supported by this adapter.

```powershell
.\loop-finder.exe 10.254.197.147 -u admin --device-type netgear_web --proxy socks5://127.0.0.1:21080 --json curric.json
```

The password is prompted privately. The proxy is optional on a directly connected
machine. Only the login form is POSTed; collection uses read-only web queries.
Credentials and cookies remain in process memory. Result JSON contains parsed
identity, STP root and port state, MAC table and broadcast/multicast rates.

Current scope is **unit 1**, at most **1000 FDB entries**, and one specified switch.
There is no automatic neighbour crawl in this mode. Neighbours, LAGs and logs are
not collected, so results explicitly report incomplete topology coverage. A MAC
learned on a port indicates reachability in that direction, not direct adjacency.
The absence of graph cycles in this limited collection is not proof of no loop.

This mode does not enable SSH, change switch settings or bypass authentication.
The local passive `--listen` mode still needs an onsite Ethernet adapter and Npcap;
a routed VPN or SOCKS tunnel cannot carry the local frames it needs.
