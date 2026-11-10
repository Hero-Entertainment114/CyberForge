# CyberForge Privacy Network – Operational Guide

## What this module protects

The privacy route applies to CyberForge's built-in search and text reader only. It does not route the OS, AI-provider calls, external tool traffic, other browsers or other applications through Tor/VPN. AI requests still go to the configured AI provider over its own connection.

## Recommended setup: Tor SOCKS5

1. Start a local Tor service yourself.
2. Confirm it exposes SOCKS5 at `127.0.0.1:9050` (or your own IP-literal endpoint).
3. Select `Tor SOCKS5` in Privacy Network & Web.
4. Apply the route, check status, then run the explicit Tor verification.
5. The reader sends hostname requests through SOCKS5 using the domain address type; it does not resolve target hostnames locally.

If the SOCKS endpoint is not ready, search/reader requests fail instead of falling back to Direct. This release supports SOCKS5 no-auth, not arbitrary SOCKS authentication schemes.

## Using WireGuard

Bring up a full-tunnel profile through the operating system. On Linux CyberForge checks the WireGuard interfaces and the route to a public probe address. This is only a route hint. Verify `AllowedIPs`, DNS, IPv6 policy and firewall kill-switch independently. CyberForge never reads or stores your WireGuard private key.

## Using a proxy

Configure an HTTP proxy endpoint. For HTTP, the request is sent as an absolute URI to that proxy; for HTTPS, CyberForge uses CONNECT. No direct fallback is implemented. Basic credentials are accepted only for a loopback proxy because this module does not support TLS-to-proxy transport.

## Search and web reading

DuckDuckGo receives the search query when selected. SearXNG receives the query when its HTTPS URL is selected; use an instance you trust. The reader fetches text-only public pages. It does not execute JavaScript, log in, accept forms, store cookies or download attachments. Redirects must be reviewed and opened manually.

## What this is not

- Not complete anonymity.
- Not a replacement for Tor Browser.
- Not a VPN provider or VPN client.
- Not a host-wide network namespace or firewall kill switch.
- Not protection against account identity, device/browser fingerprinting, OS malware, provider logs, ISP/router/DNS logs or information you choose to submit.
- The topology simulator is illustrative only; it does not generate actual network traffic or change host configuration.

For interactive browsing over Tor, use the official Tor Browser and keep it updated. Do not rely on CyberForge as the only privacy layer for high-risk activities.
