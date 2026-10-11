const TYPE_PROFILES = {
  pc: { role: "user-endpoint", zone: "user", label: "Workstation" },
  laptop: { role: "user-endpoint", zone: "user", label: "Laptop" },
  phone: { role: "user-endpoint", zone: "user", label: "Mobile device" },
  server: { role: "server", zone: "server", label: "Server" },
  router: { role: "infrastructure", zone: "core", label: "Router" },
  switch: { role: "infrastructure", zone: "access", label: "Switch" },
  gateway: { role: "gateway", zone: "gateway", label: "Gateway" },
  beacon: { role: "iot", zone: "iot", label: "BLE beacon" },
  sensor: { role: "iot", zone: "iot", label: "Sensor" },
  "iot-bulb": { role: "iot", zone: "iot", label: "IoT bulb" },
  "iot-lock": { role: "iot", zone: "iot", label: "IoT lock" },
  "iot-tag": { role: "iot", zone: "iot", label: "IoT tag" },
  "iot-camera": { role: "iot", zone: "iot", label: "IoT camera" },
  "iot-thermostat": { role: "iot", zone: "iot", label: "IoT thermostat" },
  "iot-plug": { role: "iot", zone: "iot", label: "IoT plug" },
  "usb-storage": { role: "peripheral", zone: "peripheral", label: "Removable storage" },
  "usb-keyboard": { role: "peripheral", zone: "peripheral", label: "USB keyboard" },
  "usb-mouse": { role: "peripheral", zone: "peripheral", label: "USB mouse" },
  "usb-webcam": { role: "peripheral", zone: "peripheral", label: "USB webcam" },
  "usb-audio": { role: "peripheral", zone: "peripheral", label: "USB audio" },
  "usb-printer": { role: "peripheral", zone: "peripheral", label: "USB printer" },
};

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const uniqueByTitle = (findings) => {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.severity}:${finding.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const sortFindings = (findings) =>
  uniqueByTitle(findings)
    .sort((a, b) => {
      const bySeverity = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
      if (bySeverity !== 0) return bySeverity;
      return a.title.localeCompare(b.title);
    })
    .slice(0, 4);

export const getSecurityProfile = (device = {}) => {
  const inferred = TYPE_PROFILES[device.type] || {};
  return {
    role: device.role || inferred.role || "unknown",
    zone: device.securityZone || inferred.zone || "unknown",
    label: inferred.label || device.type || "Device",
  };
};

const getNeighbors = (deviceId, devices, connections) => {
  const neighborIds = connections.reduce((acc, connection) => {
    if (connection.from === deviceId) acc.add(connection.to);
    if (connection.to === deviceId) acc.add(connection.from);
    return acc;
  }, new Set());
  return devices.filter((device) => neighborIds.has(device.id));
};

const getConnectedComponent = (startId, devices, connections) => {
  const visited = new Set();
  const queue = [startId];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || visited.has(current)) continue;
    visited.add(current);
    connections.forEach((connection) => {
      if (connection.from === current && !visited.has(connection.to)) queue.push(connection.to);
      if (connection.to === current && !visited.has(connection.from)) queue.push(connection.from);
    });
  }

  return devices.filter((device) => visited.has(device.id));
};

const hasExplicitSegmentation = (devices) => {
  const vlanIds = new Set(
    devices
      .map((device) => device.vlanId)
      .filter((value) => value !== undefined && value !== null && String(value).trim() !== "")
      .map((value) => String(value))
  );
  return vlanIds.size > 1;
};

const makeFinding = (severity, title, summary, recommendation) => ({
  severity,
  title,
  summary,
  recommendation,
});

const endpointTypes = new Set(["pc", "laptop", "phone"]);
const serverTypes = new Set(["server"]);
const gatewayTypes = new Set(["gateway"]);
const iotTypes = new Set(["beacon", "sensor", "iot-bulb", "iot-lock", "iot-tag", "iot-camera", "iot-thermostat", "iot-plug"]);
const switchTypes = new Set(["switch"]);
const routerTypes = new Set(["router"]);

export const getDeviceSecurityInsights = (device, devices, connections) => {
  if (!device) return [];

  const findings = [];
  const neighbors = getNeighbors(device.id, devices, connections);
  const component = getConnectedComponent(device.id, devices, connections);
  const componentProfiles = component.map(getSecurityProfile);
  const hasSegmentation = hasExplicitSegmentation(component);
  const profile = getSecurityProfile(device);

  if (endpointTypes.has(device.type) && device.ip) {
    findings.push(makeFinding(
      "medium",
      "Review workstation exposure",
      `${device.name} is an interactive endpoint. In a real network, unnecessary services or open management ports on user systems increase attack surface.`,
      "Keep only required services enabled, restrict remote admin access, and place user endpoints in access VLANs."
    ));
  }

  if (serverTypes.has(device.type)) {
    const peerEndpoints = component.filter((peer) => endpointTypes.has(peer.type));
    if (peerEndpoints.length > 0 && !hasSegmentation) {
      findings.push(makeFinding(
        "high",
        "Server shares a flat segment",
        `${device.name} appears reachable within the same visible segment as user endpoints. A compromised workstation could move laterally toward this higher-value asset.`,
        "Separate server workloads into a dedicated VLAN or zone and limit east-west access with ACLs or firewall rules."
      ));
    }
  }

  if (switchTypes.has(device.type)) {
    const neighborZones = new Set(neighbors.map((neighbor) => getSecurityProfile(neighbor).zone));
    const mixedTrust = neighborZones.has("user") && (neighborZones.has("server") || neighborZones.has("iot") || neighborZones.has("gateway"));
    if (mixedTrust && !hasSegmentation) {
      findings.push(makeFinding(
        "high",
        "Flat access switching",
        `${device.name} connects devices from different trust zones without visible VLAN separation. That can support discovery and lateral movement.`,
        "Introduce VLANs, access controls, and port-based policies so user, server, and IoT traffic do not share the same unrestricted access layer."
      ));
    }
    findings.push(makeFinding(
      "medium",
      "Access-layer hardening assumptions",
      `${device.name} is acting as an access switch, but the topology does not show controls such as port security, NAC, or management isolation.`,
      "Document which ports are trusted, restrict switch management access, and consider port security or NAC for endpoint-facing interfaces."
    ));
  }

  if (routerTypes.has(device.type)) {
    findings.push(makeFinding(
      "medium",
      "Protect the management plane",
      `${device.name} is a critical infrastructure node. Broad reachability to its management plane can turn a single endpoint compromise into a wider network compromise.`,
      "Restrict router administration to dedicated management paths and avoid exposing management services to general user segments."
    ));
  }

  if (gatewayTypes.has(device.type)) {
    const hasIotPeers = component.some((peer) => iotTypes.has(peer.type));
    const hasCorePeers = component.some((peer) => routerTypes.has(peer.type) || serverTypes.has(peer.type) || switchTypes.has(peer.type));
    if (hasIotPeers && hasCorePeers) {
      findings.push(makeFinding(
        "high",
        "Gateway bridges trust zones",
        `${device.name} appears to connect less-trusted Bluetooth or IoT systems toward the core network. That bridge can expand attack surface if the gateway is weakly managed.`,
        "Treat the gateway as a trust boundary, limit routes, monitor it closely, and isolate IoT traffic from user and server networks."
      ));
    }
  }

  if (iotTypes.has(device.type)) {
    findings.push(makeFinding(
      "medium",
      "IoT device risk profile",
      `${device.name} belongs to a device class that often has weaker patching, limited logging, or weaker authentication than traditional hosts.`,
      "Place IoT devices in a restricted zone, minimize reachable services, and keep management pathways separate from user traffic."
    ));
  }

  if (device.type === "usb-storage") {
    findings.push(makeFinding(
      "medium",
      "Removable media exposure",
      `${device.name} represents removable storage, which can introduce malware, data loss, or unauthorized data transfer if broadly trusted.`,
      "Limit autorun-style behavior, monitor removable media usage, and require endpoint controls for data movement."
    ));
  }

  if (component.length >= 4 && !hasSegmentation) {
    const hasMixedZones = new Set(componentProfiles.map((item) => item.zone)).size >= 2;
    if (hasMixedZones) {
      findings.push(makeFinding(
        "medium",
        "Minimal visible segmentation",
        `The visible topology around ${device.name} suggests a mostly flat network segment. Once an attacker lands on one host, east-west movement is usually easier in flat designs.`,
        "Use VLANs or routed zones to separate endpoints, servers, infrastructure, and IoT systems."
      ));
    }
  }

  if (findings.length === 0) {
    findings.push(makeFinding(
      "low",
      "No obvious topology-only issue",
      `${device.name} does not currently show a strong security concern from topology alone. This view is educational and does not replace validation of ports, services, or configuration.`,
      "Keep documenting trust zones and review what services should actually be reachable on this device."
    ));
  }

  return sortFindings(findings);
};

export const getConnectionSecurityInsights = (connection, devices, connections) => {
  if (!connection) return [];

  const findings = [];
  const fromDevice = devices.find((device) => device.id === connection.from);
  const toDevice = devices.find((device) => device.id === connection.to);
  if (!fromDevice || !toDevice) return [];

  const pair = [fromDevice.type, toDevice.type];
  const endpoints = [fromDevice, toDevice].filter((device) => endpointTypes.has(device.type));
  const switches = [fromDevice, toDevice].filter((device) => switchTypes.has(device.type));
  const gateways = [fromDevice, toDevice].filter((device) => gatewayTypes.has(device.type));
  const component = getConnectedComponent(fromDevice.id, devices, connections);
  const hasSegmentation = hasExplicitSegmentation(component) || Boolean(connection.segmented);

  if (switches.length > 0 && endpoints.length > 0 && !hasSegmentation) {
    const accessSwitch = switches[0];
    const peerDevices = getNeighbors(accessSwitch.id, devices, connections);
    const hasHighValuePeers = peerDevices.some((peer) => serverTypes.has(peer.type) || gatewayTypes.has(peer.type) || routerTypes.has(peer.type));
    findings.push(makeFinding(
      hasHighValuePeers ? "high" : "medium",
      "Potential lateral movement path",
      `${endpoints[0].name} is attached to ${accessSwitch.name}. Without VLANs or access controls, compromise of this endpoint can make discovery and peer-to-peer movement easier across the shared switch fabric.`,
      "Use access VLANs, restrict management reachability, and separate user endpoints from servers, gateways, and infrastructure devices."
    ));
  }

  if (pair.includes("server") && pair.includes("switch") && !hasSegmentation) {
    findings.push(makeFinding(
      "high",
      "Server attached to shared access layer",
      `${fromDevice.name} and ${toDevice.name} suggest a server is directly on a shared switching segment. In a flat design, user-originated compromise can move toward server workloads more easily.`,
      "Place server-facing ports into a dedicated server zone or VLAN and enforce policy between user and server segments."
    ));
  }

  if (gateways.length > 0) {
    const gateway = gateways[0];
    const gatewayPeers = getNeighbors(gateway.id, devices, connections);
    const hasIotSide = gatewayPeers.some((peer) => iotTypes.has(peer.type));
    const hasCoreSide = gatewayPeers.some((peer) => serverTypes.has(peer.type) || routerTypes.has(peer.type) || switchTypes.has(peer.type));
    if (hasIotSide && hasCoreSide) {
      findings.push(makeFinding(
        "high",
        "Bridge between low-trust and core systems",
        `${gateway.name} appears to link IoT or Bluetooth devices toward more trusted infrastructure. That can create a pivot path if the gateway or attached devices are weakly secured.`,
        "Constrain the gateway with ACLs, isolate IoT traffic, and avoid letting the bridge reach broad server or management networks."
      ));
    }
  }

  if ((getSecurityProfile(fromDevice).zone !== getSecurityProfile(toDevice).zone) && connection.direction === "both" && !hasSegmentation) {
    findings.push(makeFinding(
      "medium",
      "Broad bidirectional trust",
      `${fromDevice.name} and ${toDevice.name} have unrestricted bidirectional connectivity in the visible model. Mixed-trust links are easier to abuse when policy boundaries are not shown.`,
      "Document which protocols should cross this link and introduce segmentation or filtering where trust zones differ."
    ));
  }

  if (findings.length === 0) {
    findings.push(makeFinding(
      "low",
      "No major concern from this link alone",
      `${fromDevice.name} ↔ ${toDevice.name} does not currently show a major issue from topology alone. Real risk still depends on ports, services, and allowed traffic.`,
      "Review whether this path needs full bidirectional reachability and document intended protocol use."
    ));
  }

  return sortFindings(findings);
};
