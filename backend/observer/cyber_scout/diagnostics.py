"""Deterministic, local plain-English explanations for diagnostic evidence."""

from __future__ import annotations

PORT_GUIDANCE = {
    21: ("FTP transfers files without modern transport encryption in its usual configuration.", "Disable it if unused, or prefer SFTP/another encrypted replacement."),
    22: ("SSH is an encrypted remote administration service.", "Confirm remote login is intended, patched, and uses strong keys or passwords."),
    23: ("Telnet is an older remote-access service that commonly sends information without encryption.", "Disable Telnet if possible and use an encrypted administration service such as SSH."),
    80: ("HTTP is a web service that may send content without encryption.", "Open the service only if you recognize the device; prefer HTTPS for sensitive administration."),
    443: ("HTTPS is an encrypted web service and is common for device administration.", "Confirm the page belongs to this device and keep its software and certificate configuration current."),
    445: ("SMB provides Windows-style file and printer sharing and is frequently targeted when exposed too broadly.", "Limit access to trusted local devices, disable obsolete SMB versions, and patch the device."),
    3389: ("Remote Desktop permits interactive administration of a computer.", "Keep it local-only, require strong authentication, and disable it if it is not needed."),
    5900: ("VNC provides remote screen control and may have weak protection depending on configuration.", "Confirm it is intended and require encryption and strong authentication."),
}


def explain_open_port(port: int, service: str, level: str) -> dict[str, object]:
    meaning, action = PORT_GUIDANCE.get(
        port,
        (
            f"A service identified as {service} accepted a TCP connection on this device.",
            "Confirm that this service is expected and keep the device software updated.",
        ),
    )
    concern = "higher" if level == "higher" else "review"
    return {
        "severity": concern,
        "observation": f"TCP port {port} ({service}) accepted a connection.",
        "meaning": meaning,
        "whyItMatters": "Reachability is not proof of a vulnerability, but unexpected services increase the device's network exposure.",
        "recommendedAction": action,
        "technicalDetails": {"protocol": "tcp", "port": port, "service": service, "state": "open"},
    }


def summarize_findings(findings: list[dict[str, object]]) -> str:
    if not findings:
        return "No selected review ports accepted a connection. A filtered or timed-out response is not proof that a service is absent."
    lines = []
    for finding in findings:
        technical = finding["technicalDetails"]
        lines.append(f"{technical['port']} {technical['service']}: {finding['meaning']} {finding['recommendedAction']}")
    lines.append("An open port is an observation, not confirmation that the device is unsafe.")
    return "\n".join(lines)
