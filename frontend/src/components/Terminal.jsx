import React, { useState, useRef, useEffect } from "react";

const DEFAULT_PROMPT = "lab@network:~$";
const MAX_CAPTURE_SHOW_ROWS = 100;
const USB_TYPES = new Set(["usb-storage", "usb-keyboard", "usb-mouse", "usb-webcam", "usb-audio", "usb-printer"]);
const USB_CLASS = {
  "usb-storage": "Mass Storage",
  "usb-keyboard": "Human Interface Device",
  "usb-mouse": "Human Interface Device",
  "usb-webcam": "Video",
  "usb-audio": "Audio",
  "usb-printer": "Printer",
};

const localBtMac = () => "AA:BB:CC:10:20:30";

const MAN_PAGES = {
  man: [
    "MAN(1)",
    "",
    "NAME",
    "    man - format and display terminal command manuals",
    "",
    "SYNOPSIS",
    "    man <command>",
    "",
    "EXAMPLES",
    "    man ping",
    "    man bluetoothctl",
  ],
  ping: [
    "PING(8)",
    "",
    "NAME",
    "    ping - send ICMP ECHO_REQUEST to network host",
    "",
    "SYNOPSIS",
    "    ping <ip|device> [-c N]",
    "",
    "DESCRIPTION",
    "    Resolves device name to IP if possible, then simulates ICMP traffic.",
  ],
  ip: [
    "IP(8)",
    "",
    "NAME",
    "    ip - show / manipulate routing and device status",
    "",
    "SYNOPSIS",
    "    ip addr",
    "    show ip route",
    "    ip route",
    "    ip route add <network/cidr> via <gateway-ip>",
    "    ip route delete <network/cidr>",
    "    ip neigh",
  ],
  traceroute: [
    "TRACEROUTE(8)",
    "",
    "NAME",
    "    traceroute - print the route packets take to network host",
    "",
    "SYNOPSIS",
    "    traceroute <ip|device>",
  ],
  arp: [
    "ARP(8)",
    "",
    "NAME",
    "    arp - manipulate the system ARP cache",
    "",
    "SYNOPSIS",
    "    arp -a",
    "    clear arp",
  ],
  "show mac-address-table": [
    "SHOW-MAC-ADDRESS-TABLE(8)",
    "",
    "NAME",
    "    show mac-address-table - display learned MAC table on active switch",
    "",
    "SYNOPSIS",
    "    show mac-address-table",
  ],
  lsusb: [
    "LSUSB(8)",
    "",
    "NAME",
    "    lsusb - list USB devices",
    "",
    "SYNOPSIS",
    "    lsusb",
  ],
  lsblk: [
    "LSBLK(8)",
    "",
    "NAME",
    "    lsblk - list block devices",
    "",
    "SYNOPSIS",
    "    lsblk",
  ],
  dmesg: [
    "DMESG(1)",
    "",
    "NAME",
    "    dmesg - print or control the kernel ring buffer",
    "",
    "SYNOPSIS",
    "    dmesg",
    "    dmesg | tail",
  ],
  bluetoothctl: [
    "BLUETOOTHCTL(1)",
    "",
    "NAME",
    "    bluetoothctl - interactive Bluetooth control utility",
    "",
    "SYNOPSIS",
    "    bluetoothctl devices",
    "    bluetoothctl scan on|off",
    "    bluetoothctl pair <mac>",
    "    bluetoothctl connect <mac>",
    "    bluetoothctl info <mac>",
  ],
  ssh: [
    "SSH(1)",
    "",
    "NAME",
    "    ssh - switch command context to a simulated host",
    "",
    "SYNOPSIS",
    "    ssh <device|ip>",
    "    ssh <device|ip> via <gateway>",
    "    exit",
  ],
  ble: [
    "BLE(1)",
    "",
    "NAME",
    "    ble - interact with Bluetooth devices for monitoring/ops",
    "",
    "SYNOPSIS",
    "    ble connect <device|mac>",
    "    ble status",
    "    ble monitor",
    "    ble read <characteristic>",
    "    ble write <characteristic> <value>",
    "    ble disconnect",
  ],
  sendpkt: [
    "SENDPKT(1)",
    "",
    "NAME",
    "    sendpkt - send one synthetic packet from active ssh host",
    "",
    "SYNOPSIS",
    "    sendpkt <device|ip> [PROTO]",
  ],
  tcpdump: [
    "TCPDUMP(8)",
    "",
    "NAME",
    "    tcpdump - dump traffic on a network",
    "",
    "SYNOPSIS",
    "    tcpdump start|stop|status|show|clear",
  ],
  capture: [
    "CAPTURE(1)",
    "",
    "NAME",
    "    capture - alias for tcpdump control commands",
    "",
    "SYNOPSIS",
    "    capture start|stop|status|show|clear",
  ],
  clear: [
    "CLEAR(1)",
    "",
    "NAME",
    "    clear - clear the terminal screen",
    "",
    "SYNOPSIS",
    "    clear",
  ],
  help: [
    "HELP(1)",
    "",
    "NAME",
    "    help - show available lab commands",
    "",
    "SYNOPSIS",
    "    help",
  ],
};

export default function Terminal({
  devices,
  connections,
  packets,
  onAppendPackets,
  onClearPackets,
  onShowPackets,
  onTrafficGenerated,
  onUpdateDevice,
}) {
  const [history, setHistory] = useState([
    { type: "info", text: 'Network Lab Terminal — type "help" for usage.' },
    { type: "info", text: "Capture is OFF (use: tcpdump start)" },
  ]);
  const [input, setInput] = useState("");
  const [cmdHistory, setCmdHistory] = useState([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [loading, setLoading] = useState(false);
  const [captureEnabled, setCaptureEnabled] = useState(false);
  const [btScanEnabled, setBtScanEnabled] = useState(false);
  const [btStateByMac, setBtStateByMac] = useState({});
  const [sshSessionDeviceId, setSshSessionDeviceId] = useState(null);
  const [sshProxyGatewayId, setSshProxyGatewayId] = useState(null);
  const [bleSessionDeviceId, setBleSessionDeviceId] = useState(null);
  const [bleProxyGatewayId, setBleProxyGatewayId] = useState(null);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);
  const activeCommandAbortRef = useRef(null);

  const bluetoothDevices = devices.filter((device) => Boolean(device.btMac));
  const sshSessionDevice = sshSessionDeviceId
    ? devices.find((device) => String(device.id) === String(sshSessionDeviceId))
    : null;
  const sshProxyGateway = sshProxyGatewayId
    ? devices.find((device) => String(device.id) === String(sshProxyGatewayId))
    : null;

  // USB devices scoped to the current SSH host via canvas edges only.
  // When not in an SSH session, falls back to all USB devices labeled by host.
  const currentSshHost = sshSessionDevice || sshProxyGateway;
  const usbDevices = (() => {
    const allUsb = devices.filter((d) => USB_TYPES.has(d.type));
    if (!currentSshHost) return allUsb;
    const hostId = String(currentSshHost.id);
    const connectedIds = new Set(
      connections
        .filter((c) => String(c.from) === hostId || String(c.to) === hostId)
        .flatMap((c) => [String(c.from), String(c.to)])
    );
    return allUsb.filter((d) => connectedIds.has(String(d.id)));
  })();

  const bleSessionDevice = bleSessionDeviceId
    ? devices.find((device) => String(device.id) === String(bleSessionDeviceId))
    : null;
  const bleProxyGateway = bleProxyGatewayId
    ? devices.find((device) => String(device.id) === String(bleProxyGatewayId))
    : null;

  const prompt = bleSessionDevice
    ? bleProxyGateway
      ? `ble:${bleSessionDevice.name.toLowerCase()}@${bleProxyGateway.name.toLowerCase()}(proxy)$`
      : `ble:${bleSessionDevice.name.toLowerCase()}$`
    : sshSessionDevice
      ? sshProxyGateway
        ? `${sshSessionDevice.name.toLowerCase()}@${sshProxyGateway.name.toLowerCase()}(proxy):~$`
        : `${sshSessionDevice.name.toLowerCase()}@lab:~$`
      : DEFAULT_PROMPT;

  const parseIpv4 = (value) => {
    const text = String(value || "").trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(text)) return null;
    const octets = text.split(".").map(Number);
    if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
      return null;
    }
    return text;
  };

  const normalizeCidr = (value) => {
    const text = String(value || "").trim();
    const match = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!match) return null;
    const ip = parseIpv4(match[1]);
    const prefix = Number(match[2]);
    if (!ip || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    return `${ip}/${prefix}`;
  };

  useEffect(() => {
    if (sshSessionDeviceId && !sshSessionDevice) {
      setSshSessionDeviceId(null);
      setSshProxyGatewayId(null);
      pushLines(["SSH session closed: host no longer exists."], "info");
    }
  }, [sshSessionDeviceId, sshSessionDevice]);

  useEffect(() => {
    if (bleSessionDeviceId && !bleSessionDevice) {
      setBleSessionDeviceId(null);
      setBleProxyGatewayId(null);
      pushLines(["BLE session closed: device no longer exists."], "info");
    }
  }, [bleSessionDeviceId, bleSessionDevice]);

  const pushLines = (lines, type = "output") => {
    setHistory((prev) => [
      ...prev,
      ...lines.map((text) => ({ type, text })),
    ]);
  };

  const syncBluetoothState = () => {
    setBtStateByMac((prev) => {
      const next = {};
      bluetoothDevices.forEach((device) => {
        const mac = device.btMac.toLowerCase();
        next[mac] = prev[mac] || { paired: false, connected: false };
      });
      return next;
    });
  };

  useEffect(() => {
    syncBluetoothState();
  }, [devices]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  useEffect(() => {
    if (!loading) return undefined;

    const onWindowKeyDown = (e) => {
      if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "c") {
        e.preventDefault();
        if (activeCommandAbortRef.current) {
          activeCommandAbortRef.current.abort();
        }
      }
    };

    window.addEventListener("keydown", onWindowKeyDown);
    return () => window.removeEventListener("keydown", onWindowKeyDown);
  }, [loading]);

  const getTerminalText = () => history.map((line) => line.text).join("\n");

  const copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      pushLines(["Copied to clipboard."], "info");
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      pushLines(["Copied to clipboard."], "info");
    }
  };

  const copySelectionOrLog = async () => {
    const selected = window.getSelection()?.toString().trim();
    const text = selected && selected.length > 0 ? selected : getTerminalText();
    if (!text) {
      pushLines(["Nothing to copy."], "info");
      return;
    }
    await copyText(text);
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) {
        pushLines(["Clipboard is empty."], "info");
        return;
      }
      setInput((prev) => `${prev}${text}`);
      inputRef.current?.focus();
    } catch {
      pushLines(["Clipboard paste not allowed in this browser context."], "error");
    }
  };

  const onTerminalKeyDown = async (e) => {
    if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "c" && loading) {
      e.preventDefault();
      if (activeCommandAbortRef.current) {
        activeCommandAbortRef.current.abort();
      }
      return;
    }
    if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "c") {
      e.preventDefault();
      await copySelectionOrLog();
      return;
    }
    if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "v") {
      e.preventDefault();
      await pasteFromClipboard();
    }
  };

  const appendBlePackets = (rows) => {
    if (rows.length === 0) return;
    const result = onTrafficGenerated?.(rows);
    const deliveredPackets = Array.isArray(result?.deliveredPackets) ? result.deliveredPackets : rows;
    const droppedPackets = Array.isArray(result?.droppedPackets) ? result.droppedPackets : [];
    if (!captureEnabled) return;
    onAppendPackets([...deliveredPackets, ...droppedPackets]);
  };

  const makeBlePacket = ({ time, src, dst, len = 31, info }) => ({
    time,
    src,
    dst,
    protocol: "BLE",
    len,
    info,
  });

  const findDeviceByToken = (token) => {
    if (!token) return null;
    const normalized = token.trim().toLowerCase();
    return devices.find((device) =>
      String(device.id) === normalized ||
      String(device.name || "").toLowerCase() === normalized ||
      String(device.ip || "").toLowerCase() === normalized
    ) || null;
  };

  const findBluetoothDeviceByToken = (token) => {
    if (!token) return null;
    const normalized = token.trim().toLowerCase();
    return devices.find((device) =>
      Boolean(device.btMac) && (
        String(device.id) === normalized ||
        String(device.name || "").toLowerCase() === normalized ||
        String(device.btMac || "").toLowerCase() === normalized
      )
    ) || null;
  };

  const runCommand = async (cmd) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    setHistory((prev) => [...prev, { type: "cmd", text: `${prompt} ${trimmed}` }]);
    setCmdHistory((prev) => [trimmed, ...prev]);
    setHistIdx(-1);

    const sshProxyMatch = trimmed.match(/^ssh\s+(\S+)\s+via\s+(\S+)$/i);
    if (sshProxyMatch) {
      const target = findDeviceByToken(sshProxyMatch[1]);
      const gateway = findDeviceByToken(sshProxyMatch[2]);
      if (!target) {
        pushLines([`ssh: Could not resolve hostname ${sshProxyMatch[1]}: Name or service not known`], "error");
        return;
      }
      if (!gateway || !gateway.ip) {
        pushLines([`ssh: gateway '${sshProxyMatch[2]}' is unavailable or missing IP`], "error");
        return;
      }

      if (target.btMac && !target.ip) {
        setBleSessionDeviceId(target.id);
        setBleProxyGatewayId(gateway.id);
        setSshSessionDeviceId(null);
        setSshProxyGatewayId(null);
        pushLines([
          `Proxy BLE session established to ${target.name} via ${gateway.name}.`,
          "Use 'ble status', 'ble monitor', 'ble read <char>', 'ble write <char> <value>', or 'ble disconnect'.",
        ], "info");
      } else {
        setSshSessionDeviceId(target.id);
        setSshProxyGatewayId(gateway.id);
        setBleSessionDeviceId(null);
        setBleProxyGatewayId(null);
        pushLines([
          `Connected to ${target.name}${target.ip ? ` (${target.ip})` : ""} via proxy ${gateway.name}.`,
          "Type 'exit' to leave SSH session.",
        ], "info");
      }
      return;
    }

    const sshMatch = trimmed.match(/^ssh\s+(\S+)$/i);
    if (sshMatch) {
      const targetToken = sshMatch[1];
      const target = findDeviceByToken(targetToken);
      if (!target) {
        pushLines([`ssh: Could not resolve hostname ${targetToken}: Name or service not known`], "error");
      } else if (target.btMac && !target.ip) {
        pushLines([
          `ssh: ${target.name} is a Bluetooth endpoint and does not expose SSH directly.`,
          `Try: ssh ${target.name} via <gateway> or use 'ble connect ${target.name}'.`,
        ], "error");
      } else if (!target.ip) {
        pushLines([`ssh: ${target.name} has no IP address configured.`], "error");
      } else {
        setSshSessionDeviceId(target.id);
        setSshProxyGatewayId(null);
        setBleSessionDeviceId(null);
        setBleProxyGatewayId(null);
        pushLines([
          `Connected to ${target.name}${target.ip ? ` (${target.ip})` : ""}.`,
          "Type 'exit' to leave SSH session.",
        ], "info");
      }
      return;
    }

    const bleMatch = trimmed.match(/^ble\s+(connect\s+\S+|status|monitor|read\s+\S+|write\s+\S+\s+.+|disconnect)$/i);
    if (bleMatch) {
      const parts = trimmed.split(/\s+/);
      const action = parts[1]?.toLowerCase();

      if (action === "connect") {
        const target = findBluetoothDeviceByToken(parts[2]);
        if (!target) {
          pushLines([`ble: device '${parts[2]}' not found`], "error");
        } else {
          setBleSessionDeviceId(target.id);
          setBleProxyGatewayId(null);
          setSshSessionDeviceId(null);
          setSshProxyGatewayId(null);
          pushLines([`BLE session connected to ${target.name} (${target.btMac.toUpperCase()}).`], "info");
        }
        return;
      }

      if (action === "disconnect") {
        if (bleSessionDevice) {
          pushLines([`BLE session disconnected from ${bleSessionDevice.name}.`], "info");
          setBleSessionDeviceId(null);
          setBleProxyGatewayId(null);
        } else {
          pushLines(["No active BLE session."], "info");
        }
        return;
      }

      if (!bleSessionDevice) {
        pushLines(["No active BLE session. Use: ble connect <device|mac>"], "error");
        return;
      }

      if (action === "status") {
        pushLines([
          `BLE target: ${bleSessionDevice.name}`,
          `Address: ${bleSessionDevice.btMac.toUpperCase()}`,
          `Proxy: ${bleProxyGateway ? bleProxyGateway.name : "none"}`,
        ], "info");
        return;
      }

      if (action === "monitor") {
        const rows = [
          makeBlePacket({ time: 0.0412, src: localBtMac(), dst: bleSessionDevice.btMac, len: 27, info: "ATT Read By Type Req Handle:0x0001 UUID:0x2A19" }),
          makeBlePacket({ time: 0.0448, src: bleSessionDevice.btMac, dst: localBtMac(), len: 25, info: "ATT Read By Type Rsp Battery Level: 93%" }),
          makeBlePacket({ time: 0.0524, src: bleSessionDevice.btMac, dst: localBtMac(), len: 31, info: `Notify telemetry from ${bleSessionDevice.name}` }),
        ];
        appendBlePackets(rows);
        pushLines([`Monitoring BLE telemetry from ${bleSessionDevice.name}...`], "info");
        return;
      }

      if (action === "read") {
        const characteristic = parts[2];
        appendBlePackets([
          makeBlePacket({ time: 0.0611, src: localBtMac(), dst: bleSessionDevice.btMac, len: 24, info: `ATT Read Req ${characteristic}` }),
          makeBlePacket({ time: 0.0643, src: bleSessionDevice.btMac, dst: localBtMac(), len: 29, info: `ATT Read Rsp ${characteristic}=simulated-value` }),
        ]);
        pushLines([`ble read ${characteristic}: simulated-value`], "info");
        return;
      }

      if (action === "write") {
        const characteristic = parts[2];
        const value = parts.slice(3).join(" ");
        appendBlePackets([
          makeBlePacket({ time: 0.0722, src: localBtMac(), dst: bleSessionDevice.btMac, len: 28, info: `ATT Write Req ${characteristic}=${value}` }),
          makeBlePacket({ time: 0.0749, src: bleSessionDevice.btMac, dst: localBtMac(), len: 21, info: "ATT Write Rsp status=ok" }),
        ]);
        pushLines([`ble write ${characteristic}: ok`], "info");
        return;
      }
    }

    if (trimmed === "exit") {
      if (sshSessionDevice) {
        pushLines([`logout from ${sshSessionDevice.name}`], "info");
        setSshSessionDeviceId(null);
        setSshProxyGatewayId(null);
      } else if (bleSessionDevice) {
        pushLines([`BLE session closed from ${bleSessionDevice.name}`], "info");
        setBleSessionDeviceId(null);
        setBleProxyGatewayId(null);
      } else {
        pushLines(["exit"], "info");
      }
      return;
    }

    const sendPktMatch = trimmed.match(/^sendpkt\s+(\S+)(?:\s+(\S+))?$/i);
    if (sendPktMatch) {
      if (!sshSessionDevice || !sshSessionDevice.ip) {
        pushLines(["sendpkt requires an active SSH session on a host with an IP address."], "error");
        return;
      }
      const targetToken = sendPktMatch[1];
      const protocol = (sendPktMatch[2] || "UDP").toUpperCase();
      const targetDevice = findDeviceByToken(targetToken);
      if (!targetDevice || !targetDevice.ip) {
        pushLines([`sendpkt: target '${targetToken}' not found or missing IP`], "error");
        return;
      }
      const syntheticPacket = [{
        time: Number((0.001 + Math.random() * 0.01).toFixed(4)),
        src: sshSessionDevice.ip,
        dst: targetDevice.ip,
        protocol,
        len: 64,
        info: `Synthetic ${protocol} payload from ${sshSessionDevice.name} to ${targetDevice.name}`,
      }];
      const result = onTrafficGenerated?.(syntheticPacket);
      const deliveredPackets = Array.isArray(result?.deliveredPackets) ? result.deliveredPackets : syntheticPacket;
      const droppedPackets = Array.isArray(result?.droppedPackets) ? result.droppedPackets : [];
      if (captureEnabled) {
        onAppendPackets([...deliveredPackets, ...droppedPackets]);
      }
      pushLines([
        `sendpkt: ${sshSessionDevice.name} -> ${targetDevice.name} (${protocol})`,
        `delivered=${deliveredPackets.length} dropped=${droppedPackets.length}`,
      ], droppedPackets.length > 0 ? "error" : "info");
      return;
    }

    if (trimmed === "clear arp") {
      if (!sshSessionDevice) {
        pushLines(["clear arp: run this command from an ssh host context"], "error");
        return;
      }
      onUpdateDevice?.(sshSessionDevice.id, { arp_table: {} });
      pushLines([`clear arp: cleared ARP cache on ${sshSessionDevice.name}`], "info");
      return;
    }

    if (trimmed === "clear") {
      setHistory([]);
      return;
    }

    const manMatch = trimmed.match(/^man\s+(.+)$/i);
    if (manMatch) {
      const topic = manMatch[1].trim().toLowerCase();
      const page = MAN_PAGES[topic];
      if (page) {
        pushLines(page);
      } else {
        pushLines([`No manual entry for ${topic}`], "error");
      }
      return;
    }

    if (trimmed === "ip addr" || trimmed === "ip a") {
      if (devices.length === 0) {
        pushLines(["No interfaces configured."], "info");
      } else {
        const lines = [];
        devices.forEach((device, index) => {
          lines.push(`${index + 1}: ${device.name.toLowerCase()}: <UP> mtu 1500`);
          lines.push(`    inet ${device.ip || "unassigned"} scope global ${device.name.toLowerCase()}`);
        });
        pushLines(lines);
      }
      return;
    }

    const routeAddMatch = trimmed.match(/^ip\s+route\s+add\s+(\S+)\s+via\s+(\S+)$/i);
    if (routeAddMatch) {
      if (!sshSessionDevice) {
        pushLines(["ip route add: run this command from an ssh host context"], "error");
        return;
      }
      const network = normalizeCidr(routeAddMatch[1]);
      const gateway = parseIpv4(routeAddMatch[2]);
      if (!network || !gateway) {
        pushLines(["ip route add: invalid syntax (expected: ip route add <network/cidr> via <gateway-ip>)"], "error");
        return;
      }
      const existing = Array.isArray(sshSessionDevice.routes) ? sshSessionDevice.routes : [];
      const deduped = existing.filter((route) => normalizeCidr(route.network) !== network);
      const nextRoutes = [...deduped, { network, via: gateway }];
      onUpdateDevice?.(sshSessionDevice.id, { routes: nextRoutes });
      pushLines([`ip route add: ${network} via ${gateway}`], "info");
      return;
    }

    const routeDeleteMatch = trimmed.match(/^ip\s+route\s+delete\s+(\S+)$/i);
    if (routeDeleteMatch) {
      if (!sshSessionDevice) {
        pushLines(["ip route delete: run this command from an ssh host context"], "error");
        return;
      }
      const network = normalizeCidr(routeDeleteMatch[1]);
      if (!network) {
        pushLines(["ip route delete: invalid network (expected: <network/cidr>)"], "error");
        return;
      }
      const existing = Array.isArray(sshSessionDevice.routes) ? sshSessionDevice.routes : [];
      const nextRoutes = existing.filter((route) => normalizeCidr(route.network) !== network);
      if (nextRoutes.length === existing.length) {
        pushLines([`ip route delete: route not found (${network})`], "error");
        return;
      }
      onUpdateDevice?.(sshSessionDevice.id, { routes: nextRoutes });
      pushLines([`ip route delete: removed ${network}`], "info");
      return;
    }

    if (trimmed === "ip neigh" || trimmed === "arp -a") {
      if (!sshSessionDevice) {
        pushLines(["arp -a: run this command from an ssh host context"], "error");
        return;
      }
      const table = sshSessionDevice.arp_table || {};
      const entries = Object.entries(table)
        .filter(([ip, mac]) => Boolean(ip) && Boolean(mac))
        .sort((a, b) => a[0].localeCompare(b[0]));
      if (entries.length === 0) {
        pushLines(["(no arp entries)"], "info");
      } else {
        const lines = entries.map(([ip, mac]) => `${ip} dev eth0 lladdr ${String(mac).toLowerCase()} REACHABLE`);
        pushLines(lines);
      }
      return;
    }

    if (trimmed === "show mac-address-table") {
      if (!sshSessionDevice) {
        pushLines(["show mac-address-table: run this command from an ssh switch context"], "error");
        return;
      }
      if (String(sshSessionDevice.type || "").toLowerCase() !== "switch") {
        pushLines([`show mac-address-table: ${sshSessionDevice.name} is not a switch`], "error");
        return;
      }
      const table = sshSessionDevice.mac_table || {};
      const entries = Object.entries(table)
        .filter(([mac, port]) => Boolean(mac) && Boolean(port))
        .sort((a, b) => a[0].localeCompare(b[0]));
      if (entries.length === 0) {
        pushLines([
          `${sshSessionDevice.name} MAC Address Table`,
          "(empty)",
        ], "info");
      } else {
        const rows = [
          `${sshSessionDevice.name} MAC Address Table`,
          "",
          "MAC Address        Port",
          ...entries.map(([mac, port]) => `${mac.padEnd(18, " ")}${port}`),
        ];
        pushLines(rows, "info");
      }
      return;
    }

    if (trimmed === "lsusb") {
      if (!currentSshHost) {
        pushLines(["lsusb: not attached to a host — ssh into a device first"], "error");
        return;
      }
      if (usbDevices.length === 0) {
        pushLines([`lsusb: no USB devices connected to ${currentSshHost.name}`], "info");
      } else {
        const lines = usbDevices.map((device, index) => {
          const devNo = String(index + 2).padStart(3, "0");
          const vendor = (1000 + index * 7).toString(16).padStart(4, "0");
          const product = (2000 + index * 13).toString(16).padStart(4, "0");
          return `Bus 001 Device ${devNo}: ID ${vendor}:${product} ${device.name} (${USB_CLASS[device.type] || "USB Device"})`;
        });
        pushLines(lines);
      }
      return;
    }

    if (trimmed === "lsblk") {
      if (!currentSshHost) {
        pushLines(["lsblk: not attached to a host — ssh into a device first"], "error");
        return;
      }
      const storage = usbDevices.filter((device) => device.type === "usb-storage");
      const lines = ["NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT", "sda      8:0    0  64G  0 disk /"];
      storage.forEach((device, index) => {
        lines.push(`sdb${index}    8:${16 + index}    1  32G  0 disk /media/${device.name.toLowerCase()}`);
      });
      pushLines(lines, "info");
      return;
    }

    if (trimmed === "dmesg" || trimmed === "dmesg | tail" || trimmed === "dmesg | tail -n 20") {
      if (!currentSshHost) {
        pushLines(["dmesg: not attached to a host — ssh into a device first"], "error");
        return;
      }
      const events = [
        "[    0.000000] Linux version 6.8.0-networklab (simulated)",
        "[    1.428511] usbcore: registered new interface driver usbfs",
      ];
      usbDevices.forEach((device, index) => {
        events.push(`[    ${10 + index}.104201] usb 1-${index + 1}: new high-speed USB device number ${index + 2} using xhci_hcd`);
        events.push(`[    ${10 + index}.203947] usb 1-${index + 1}: Product: ${device.name}`);
      });
      bluetoothDevices.forEach((device, index) => {
        events.push(`[    ${20 + index}.553102] Bluetooth: hci0: discovered LE device ${device.btMac.toUpperCase()} (${device.name})`);
      });
      pushLines(trimmed === "dmesg" ? events : events.slice(-20));
      return;
    }

    const bluetoothMatch = trimmed.match(/^bluetoothctl\s+(scan\s+(on|off)|devices|pair\s+\S+|connect\s+\S+|info\s+\S+)$/i);
    if (bluetoothMatch) {
      const parts = trimmed.split(/\s+/);
      const action = parts[1]?.toLowerCase();

      if (action === "scan") {
        const mode = parts[2]?.toLowerCase();
        if (mode === "on") {
          setBtScanEnabled(true);
          syncBluetoothState();
          if (bluetoothDevices.length === 0) {
            pushLines(["Discovery started", "No Bluetooth devices found in topology."], "info");
          } else {
            const discovered = bluetoothDevices.map((device) => `[NEW] Device ${device.btMac.toUpperCase()} ${device.name}`);
            pushLines(["Discovery started", ...discovered], "info");
            appendBlePackets(
              bluetoothDevices.map((device, index) =>
                makeBlePacket({
                  time: Number((0.001 + index * 0.0008).toFixed(4)),
                  src: device.btMac,
                  dst: "ff:ff:ff:ff:ff:ff",
                  len: 39,
                  info: `ADV_IND ${device.name} RSSI=-${48 + index}dBm`,
                })
              )
            );
          }
        } else {
          setBtScanEnabled(false);
          pushLines(["Discovery stopped"], "info");
        }
        return;
      }

      if (action === "devices") {
        pushLines(
          bluetoothDevices.length === 0
            ? ["No default controller available"]
            : bluetoothDevices.map((device) => `Device ${device.btMac.toUpperCase()} ${device.name}`),
          "info"
        );
        return;
      }

      const targetToken = parts[2]?.toLowerCase();
      const targetDevice = bluetoothDevices.find(
        (device) => device.btMac.toLowerCase() === targetToken || device.name.toLowerCase() === targetToken
      );

      if (!targetDevice) {
        pushLines([`Device ${parts[2]} not available`], "error");
        return;
      }

      const macKey = targetDevice.btMac.toLowerCase();

      if (action === "pair") {
        setBtStateByMac((prev) => ({
          ...prev,
          [macKey]: { ...(prev[macKey] || {}), paired: true, connected: false },
        }));
        pushLines([
          `Attempting to pair with ${targetDevice.btMac.toUpperCase()}`,
          `[CHG] Device ${targetDevice.btMac.toUpperCase()} Paired: yes`,
          "Pairing successful",
        ], "info");
        appendBlePackets([
          makeBlePacket({ time: 0.0101, src: localBtMac(), dst: targetDevice.btMac, len: 23, info: "LL_PAIRING_REQ io_cap=KeyboardDisplay mitm=1 bond=1" }),
          makeBlePacket({ time: 0.0117, src: targetDevice.btMac, dst: localBtMac(), len: 23, info: "LL_PAIRING_RSP io_cap=NoInputNoOutput mitm=0" }),
          makeBlePacket({ time: 0.0139, src: targetDevice.btMac, dst: localBtMac(), len: 17, info: "SMP_PAIRING_COMPLETE status=success" }),
        ]);
        return;
      }

      if (action === "connect") {
        const current = btStateByMac[macKey] || { paired: false, connected: false };
        if (!current.paired) {
          pushLines(["Failed to connect: org.bluez.Error.NotPaired"], "error");
          appendBlePackets([
            makeBlePacket({ time: 0.0201, src: localBtMac(), dst: targetDevice.btMac, len: 17, info: "CONNECT_REQ rejected (not paired)" }),
          ]);
        } else {
          setBtStateByMac((prev) => ({
            ...prev,
            [macKey]: { ...(prev[macKey] || {}), paired: true, connected: true },
          }));
          pushLines([
            `Attempting to connect to ${targetDevice.btMac.toUpperCase()}`,
            "Connection successful",
          ], "info");
          appendBlePackets([
            makeBlePacket({ time: 0.0204, src: localBtMac(), dst: targetDevice.btMac, len: 21, info: "CONNECT_REQ interval=36 latency=0 timeout=400" }),
            makeBlePacket({ time: 0.0216, src: targetDevice.btMac, dst: localBtMac(), len: 15, info: "LL_CONNECTION_COMPLETE role=peripheral" }),
          ]);
        }
        return;
      }

      if (action === "info") {
        const current = btStateByMac[macKey] || { paired: false, connected: false };
        pushLines([
          `Device ${targetDevice.btMac.toUpperCase()} (${targetDevice.name})`,
          `\tName: ${targetDevice.name}`,
          `\tAlias: ${targetDevice.name}`,
          `\tPaired: ${current.paired ? "yes" : "no"}`,
          `\tTrusted: ${current.paired ? "yes" : "no"}`,
          `\tConnected: ${current.connected ? "yes" : "no"}`,
          `\tRSSI: ${btScanEnabled ? "-54" : "n/a"}`,
        ]);
        appendBlePackets([
          makeBlePacket({ time: 0.0252, src: localBtMac(), dst: targetDevice.btMac, len: 27, info: "ATT Read By Group Type Req (Primary Services)" }),
          makeBlePacket({ time: 0.0261, src: targetDevice.btMac, dst: localBtMac(), len: 31, info: "ATT Read By Group Type Rsp (GATT, Device Information)" }),
        ]);
        return;
      }
    }

    const captureMatch = trimmed.match(/^(capture|tcpdump)\s+(start|stop|clear|show|status)$/i);
    if (captureMatch) {
      const action = captureMatch[2].toLowerCase();
      if (action === "start") {
        if (captureEnabled) {
          pushLines(["Capture is already running."], "info");
        } else {
          setCaptureEnabled(true);
          pushLines(["Capture started."], "info");
        }
      } else if (action === "stop") {
        if (!captureEnabled) {
          pushLines(["Capture is already stopped."], "info");
        } else {
          setCaptureEnabled(false);
          pushLines(["Capture stopped."], "info");
        }
      } else if (action === "clear") {
        onClearPackets();
        pushLines(["Capture buffer cleared."], "info");
      } else if (action === "show") {
        onShowPackets();
        if (packets.length === 0) {
          pushLines(["No captured packets."], "info");
        } else {
          const visibleRows = packets.slice(-MAX_CAPTURE_SHOW_ROWS);
          const header = [
            `Captured packets: ${packets.length}`,
            "No.    Time       Source            Destination       Proto  Len  Info",
          ];
          const rows = visibleRows.map((packet) => {
            const no = String(packet.no ?? "").padEnd(6, " ");
            const time = String(packet.time ?? "").padEnd(10, " ");
            const src = String(packet.src ?? "").slice(0, 16).padEnd(16, " ");
            const dst = String(packet.dst ?? "").slice(0, 16).padEnd(16, " ");
            const proto = String(packet.protocol ?? "").padEnd(6, " ");
            const len = String(packet.len ?? "").padEnd(4, " ");
            const info = String(packet.info ?? "");
            return `${no}${time}${src}${dst}${proto}${len}${info}`;
          });
          const note = packets.length > MAX_CAPTURE_SHOW_ROWS ? [`Showing last ${MAX_CAPTURE_SHOW_ROWS} packets.`] : [];
          pushLines([...header, ...rows, ...note, "Packet log panel updated."], "info");
        }
      } else if (action === "status") {
        pushLines([
          captureEnabled ? "tcpdump: capture running" : "tcpdump: capture stopped",
          `buffered packets: ${packets.length}`,
        ], "info");
      }
      return;
    }

    if (trimmed === "help") {
      pushLines([
        "Available commands:",
        "  ping <ip|device> [-c N]  - send ICMP echo requests",
        "  traceroute <ip|device>   - trace route hop-by-hop",
        "  ssh <device|ip>          - open host command context",
        "  ssh <target> via <gateway> - proxy session via gateway",
        "  sendpkt <dst> [proto]    - send a synthetic packet from ssh host",
        "  ble connect <device|mac> - open BLE monitoring session",
        "  ble status|monitor       - inspect BLE target telemetry",
        "  ble read|write           - simulate BLE GATT operations",
        "  ble disconnect           - close BLE session",
        "  exit                     - close ssh host context",
        "  ip addr | ip a           - show device interfaces",
        "  show ip route | ip route - show host route table",
        "  ip route add <net> via <gw> - add static route",
        "  ip route delete <net>    - remove static route",
        "  ip neigh | arp -a        - show neighbor table",
        "  clear arp                - clear ARP cache on active host",
        "  show mac-address-table   - show learned switch MAC entries",
        "  lsusb                    - list USB/peripheral devices",
        "  lsblk                    - list block/removable storage",
        "  dmesg | dmesg | tail     - show kernel device logs",
        "  bluetoothctl devices     - list Bluetooth devices",
        "  bluetoothctl scan on|off - start/stop BT discovery",
        "  bluetoothctl pair <mac>  - pair with Bluetooth device",
        "  bluetoothctl connect <mac> - connect paired device",
        "  bluetoothctl info <mac>  - show Bluetooth device details",
        "  tcpdump start|stop       - control packet capture",
        "  tcpdump clear|show       - clear/show capture buffer",
        "  tcpdump status           - show capture state",
        "  capture ...              - alias of tcpdump",
        "  man <command>            - show command manual",
        "  help                     - show this help message",
        "  clear                    - clear terminal output",
      ]);
      return;
    }

    setLoading(true);
    const abortController = new AbortController();
    activeCommandAbortRef.current = abortController;
    try {
      const pingByName = trimmed.match(/^ping\s+(\S+)(.*)$/i);
      const tracerouteByName = trimmed.match(/^traceroute\s+(\S+)(.*)$/i);
      let normalizedCommand = trimmed;
      if (pingByName) {
        const target = pingByName[1].toLowerCase();
        const suffix = pingByName[2] || "";
        const matched = devices.find((device) => device.name.toLowerCase() === target && device.ip);
        if (matched) {
          normalizedCommand = `ping ${matched.ip}${suffix}`;
        }
      } else if (tracerouteByName) {
        const target = tracerouteByName[1].toLowerCase();
        const suffix = tracerouteByName[2] || "";
        const matched = devices.find((device) => device.name.toLowerCase() === target && device.ip);
        if (matched) {
          normalizedCommand = `traceroute ${matched.ip}${suffix}`;
        }
      }

      const response = await fetch("/api/run-command", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          command: normalizedCommand,
          devices,
          connections,
          sourceDeviceId: sshProxyGateway?.id || sshSessionDevice?.id || null,
        }),
        signal: abortController.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const { output = [], packets: generatedPackets = [], deviceUpdates = [] } = await response.json();
      if (Array.isArray(deviceUpdates) && deviceUpdates.length > 0) {
        deviceUpdates.forEach((update) => {
          if (!update?.id) return;
          const fields = {};
          if (update.mac_table && typeof update.mac_table === "object") {
            fields.mac_table = update.mac_table;
          }
          if (update.arp_table && typeof update.arp_table === "object") {
            fields.arp_table = update.arp_table;
          }
          if (Object.keys(fields).length > 0) {
            onUpdateDevice?.(update.id, fields);
          }
        });
      }
      pushLines(output);
      if (generatedPackets.length > 0) {
        const result = onTrafficGenerated?.(generatedPackets);
        const deliveredPackets = Array.isArray(result?.deliveredPackets) ? result.deliveredPackets : generatedPackets;
        const droppedPackets = Array.isArray(result?.droppedPackets) ? result.droppedPackets : [];
        if (captureEnabled) {
          onAppendPackets([...deliveredPackets, ...droppedPackets]);
        }
        if (droppedPackets.length > 0) {
          const reasonCounts = droppedPackets.reduce((acc, packet) => {
            const match = String(packet.info || "").match(/^DROP \(([^)]+)\)/);
            const reason = match?.[1] || "unknown";
            acc[reason] = (acc[reason] || 0) + 1;
            return acc;
          }, {});
          const details = Object.entries(reasonCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([reason, count]) => `${reason}:${count}`)
            .join(", ");
          pushLines([`[sim] dropped by link conditions: ${droppedPackets.length} (${details})`], "info");
        }
      }
    } catch (err) {
      if (err?.name === "AbortError") {
        pushLines(["^C", "command interrupted"], "error");
      } else {
        pushLines([`Error: ${err.message}`], "error");
      }
    } finally {
      if (activeCommandAbortRef.current === abortController) {
        activeCommandAbortRef.current = null;
      }
      setLoading(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === "c" && loading) {
      e.preventDefault();
      if (activeCommandAbortRef.current) {
        activeCommandAbortRef.current.abort();
      }
      return;
    }
    if (e.key === "Enter") {
      runCommand(input);
      setInput("");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(histIdx + 1, cmdHistory.length - 1);
      setHistIdx(next);
      setInput(cmdHistory[next] || "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.max(histIdx - 1, -1);
      setHistIdx(next);
      setInput(next === -1 ? "" : cmdHistory[next] || "");
    }
  };

  return (
    <div className="terminal" onKeyDown={onTerminalKeyDown}>
      <div className="terminal-output">
        {history.map((line, i) => (
          <div key={i} className={`terminal-line line-${line.type}`}>
            {line.text}
          </div>
        ))}
        {loading && <div className="terminal-line line-info">Running…</div>}
        <div ref={bottomRef} />
      </div>

      <div className="terminal-input-row">
        <button className="terminal-tool" onClick={copySelectionOrLog} disabled={loading}>
          Copy Log
        </button>
        <button className="terminal-tool" onClick={pasteFromClipboard} disabled={loading}>
          Paste
        </button>
        <span className="terminal-prompt">{prompt}</span>
        <input
          ref={inputRef}
          className="terminal-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder='ping 192.168.1.x'
          spellCheck={false}
          autoComplete="off"
          disabled={loading}
        />
      </div>
    </div>
  );
}
