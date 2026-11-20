NetMonitor Pro 3.1 REAL

This project builds an Android APK with:
- Real VpnService capture without root.
- Real tun2socks engine (hev-socks5-tunnel) built as native libraries.
- TCP destination host/IP + port logging at the SOCKS5 boundary.
- UDP destination host/IP + port logging.
- Select installed applications to route through the VPN.
- Port range filter and optional game-only filter.
- CSV/JSON export.
- Native tunnel packet counters.

Important Android limitation:
A VpnService sees traffic routed through its TUN interface, not an authoritative per-packet app identity. App selection is therefore implemented with VpnService.Builder.addAllowedApplication().

Build:
1. Upload all flat files to the repository root.
2. Open Actions -> Build NetMonitor Pro APK.
3. Run workflow.
4. Download the NetMonitor-Pro-APK artifact.


Build fix 3.2: NativeTunnelService JNI bridge is embedded in MonitorVpnService.java to prevent the flat-file GitHub workflow from omitting the class.
