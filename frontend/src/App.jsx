
import React, { useState, useCallback, useEffect, useRef } from "react";
import NetworkCanvas from "./components/NetworkCanvas";
import Terminal from "./components/Terminal";
import PacketLog from "./components/PacketLog";

let _id = 1;
const uid = () => String(_id++);
const BLUETOOTH_TYPES = new Set([
  "phone",
  "laptop",
  "beacon",
  "sensor",
  "gateway",
  "iot-bulb",
  "iot-lock",
  "iot-tag",
]);
const NON_IP_CAPABLE_TYPES = new Set([
  "usb-storage",
  "usb-keyboard",
  "usb-mouse",
  "usb-webcam",
  "usb-audio",
  "usb-printer",
  "beacon",
  "sensor",
  "iot-tag",
]);

const makeBtMac = () =>
  Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0"))
    .join(":");

const makeStableMac = (seed) => {
  const text = String(seed ?? "0");
  let hash = 2166136261;
  for (const ch of text) {
    hash ^= ch.charCodeAt(0);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  const bytes = [0x02, 0x00, 0x00, (hash >>> 16) & 0xff, (hash >>> 8) & 0xff, hash & 0xff];
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join(":");
};

const DEFAULT_LINK_CONDITIONS = {
  lossPct: 0,
  latencyMs: 0,
  jitterMs: 0,
  queueLimitPkts: 200,
  bandwidthPps: 100,
  redEnabled: false,
  redMinTh: 80,
  redMaxTh: 150,
  redMaxDropPct: 30,
  blocked: false,
};

export default function App() {
  const [devices, setDevices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [capturedPackets, setCapturedPackets] = useState([]);
  const [displayedPackets, setDisplayedPackets] = useState([]);
  const [trafficStats, setTrafficStats] = useState({});
  const [ipTrafficStats, setIpTrafficStats] = useState({});
  const [linkTrafficStats, setLinkTrafficStats] = useState({});
  const [packetFlights, setPacketFlights] = useState([]);
  const [rightPanelOpen, setRightPanelOpen] = useState(true);
  const linkRuntimeRef = useRef({});
  const flightTimeoutsRef = useRef([]);

  useEffect(() => {
    return () => {
      flightTimeoutsRef.current.forEach((timeoutId) => clearTimeout(timeoutId));
      flightTimeoutsRef.current = [];
    };
  }, []);

  useEffect(() => {
    setDevices((prev) => {
      let changed = false;
      const next = prev.map((device) => {
        if (!device?.name) return device;
        if (!device.type?.startsWith("usb-")) return device;
        if (!device.name.startsWith("USB-")) return device;
        changed = true;
        return { ...device, name: device.name.replace(/^USB-/, "") };
      });
      return changed ? next : prev;
    });
  }, [devices.length]);

  useEffect(() => {
    setDevices((prev) => {
      let changed = false;
      const next = prev.map((device) => {
        if (!device) return device;
        if (!NON_IP_CAPABLE_TYPES.has(device.type)) return device;
        if (!device.ip) return device;
        changed = true;
        return { ...device, ip: "" };
      });
      return changed ? next : prev;
    });
  }, [devices]);

  useEffect(() => {
    setDevices((prev) => {
      let changed = false;
      const next = prev.map((device) => {
        if (!device) return device;
        const patch = {};
        if (!device.mac && !NON_IP_CAPABLE_TYPES.has(device.type)) {
          patch.mac = makeStableMac(device.id || device.name || device.type);
        }
        if (!NON_IP_CAPABLE_TYPES.has(device.type) && (typeof device.arp_table !== "object" || device.arp_table === null)) {
          patch.arp_table = {};
        }
        if (device.type === "switch" && (typeof device.mac_table !== "object" || device.mac_table === null)) {
          patch.mac_table = {};
        }
        if (Object.keys(patch).length === 0) return device;
        changed = true;
        return { ...device, ...patch };
      });
      return changed ? next : prev;
    });
  }, [devices]);

  useEffect(() => {
    const activeKeys = new Set(connections.map((conn) => `${conn.from}->${conn.to}`));
    const nextRuntime = {};
    Object.entries(linkRuntimeRef.current).forEach(([key, runtime]) => {
      if (activeKeys.has(key)) {
        nextRuntime[key] = runtime;
      }
    });
    linkRuntimeRef.current = nextRuntime;
  }, [connections]);

  const addDevice = useCallback((type, x, y) => {
    const names = {
      pc: "PC",
      server: "Server",
      router: "Router",
      switch: "Switch",
      phone: "Phone",
      laptop: "Laptop",
      beacon: "BLE-Beacon",
      sensor: "BLE-Sensor",
      gateway: "BT-Gateway",
      "iot-bulb": "IoT-Bulb",
      "iot-lock": "IoT-Lock",
      "iot-tag": "IoT-Tag",
      "iot-camera": "IoT-Camera",
      "iot-thermostat": "IoT-Thermostat",
      "iot-plug": "IoT-Plug",
      "usb-storage": "Storage",
      "usb-keyboard": "Keyboard",
      "usb-mouse": "Mouse",
      "usb-webcam": "Webcam",
      "usb-audio": "Audio",
      "usb-printer": "Printer",
    };
    const id = uid();
    setDevices((prev) => [
      ...prev,
      {
        id,
        type,
        name: `${names[type] || type}-${id}`,
        ip: "",
        routes: [],
        mac: NON_IP_CAPABLE_TYPES.has(type) ? "" : makeStableMac(id),
        arp_table: NON_IP_CAPABLE_TYPES.has(type) ? undefined : {},
        mac_table: type === "switch" ? {} : undefined,
        btMac: BLUETOOTH_TYPES.has(type) ? makeBtMac() : "",
        x,
        y,
      },
    ]);
  }, []);

  const updateDevice = useCallback((id, fields) => {
    setDevices((prev) =>
      prev.map((d) => (d.id === id ? { ...d, ...fields } : d))
    );
  }, []);

  const removeDevice = useCallback((id) => {
    setDevices((prev) => prev.filter((d) => d.id !== id));
    setConnections((prev) =>
      prev.filter((c) => c.from !== id && c.to !== id)
    );
    setTrafficStats((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    setIpTrafficStats((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    setLinkTrafficStats((prev) => {
      const next = {};
      Object.entries(prev).forEach(([key, value]) => {
        const [fromId, toId] = key.split("->");
        if (fromId !== id && toId !== id) {
          next[key] = value;
        }
      });
      return next;
    });
    setPacketFlights((prev) =>
      prev.filter((flight) => flight.fromId !== id && flight.toId !== id)
    );
  }, []);

  const addConnection = useCallback((from, to, direction = "both", transport = "cat") => {
    setConnections((prev) => {
      const existing = prev.find(
        (c) => (c.from === from && c.to === to) || (c.from === to && c.to === from)
      );
      if (!existing) {
        return [...prev, {
          from,
          to,
          direction,
          transport,
          conditions: { ...DEFAULT_LINK_CONDITIONS },
        }];
      }
      return prev.map((c) => {
        if ((c.from === from && c.to === to) || (c.from === to && c.to === from)) {
          return {
            ...c,
            direction,
            transport,
            conditions: { ...DEFAULT_LINK_CONDITIONS, ...(c.conditions || {}) },
          };
        }
        return c;
      });
    });
  }, []);

  const updateConnection = useCallback((from, to, fields) => {
    setConnections((prev) =>
      prev.map((conn) => {
        if ((conn.from === from && conn.to === to) || (conn.from === to && conn.to === from)) {
          const mergedConditions = {
            ...DEFAULT_LINK_CONDITIONS,
            ...(conn.conditions || {}),
            ...(fields.conditions || {}),
          };
          return { ...conn, ...fields, conditions: mergedConditions };
        }
        return conn;
      })
    );
  }, []);

  const appendCapturedPackets = useCallback((newPkts) => {
    setCapturedPackets((prev) => {
      const offset = prev.length;
      return [
        ...prev,
        ...newPkts.map((p, i) => ({ ...p, no: offset + i + 1 })),
      ];
    });
  }, []);

  const clearCapturedPackets = useCallback(() => {
    setCapturedPackets([]);
    setDisplayedPackets([]);
  }, []);

  const applyTrafficPackets = useCallback((newPkts) => {
    if (!Array.isArray(newPkts) || newPkts.length === 0) {
      return { deliveredPackets: [], droppedPackets: [] };
    }

    const findDeviceIdByAddress = (addr) => {
      if (!addr) return null;
      const normalized = String(addr).toLowerCase();
      const device = devices.find((d) =>
        d.ip === addr ||
        (d.btMac && d.btMac.toLowerCase() === normalized) ||
        d.name.toLowerCase() === normalized
      );
      return device?.id || null;
    };

    const deliveredPackets = [];
    const droppedPackets = [];
    const trafficIncrements = [];
    const linkIncrements = [];
    const flights = [];

    const toNumber = (value, fallback = 0) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : fallback;
    };

    newPkts.forEach((packet) => {
      const srcId = findDeviceIdByAddress(packet.src);
      const dstId = findDeviceIdByAddress(packet.dst);

      if (!srcId || !dstId) {
        deliveredPackets.push(packet);
        return;
      }

      const conn = connections.find(
        (c) =>
          (c.from === srcId && c.to === dstId) ||
          (c.from === dstId && c.to === srcId)
      );
      const protocol = String(packet.protocol || "").toUpperCase();
      const isIpTraffic = ["ICMP", "ARP", "TCP", "UDP", "IP", "IPV6"].includes(protocol);

      const dropPacket = (reason, linkKey, blocked = false, queue = false, red = false) => {
        droppedPackets.push({
          ...packet,
          status: "dropped",
          info: `DROP (${reason})${packet.info ? ` ${packet.info}` : ""}`,
        });
        if (linkKey) {
          linkIncrements.push({ type: "drop", key: linkKey, blocked, queue, red });
        }
      };

      if (!conn) {
        dropPacket("no-link", null, false);
        return;
      }

      const direction = conn.direction || "both";
      const isForward = conn.from === srcId && conn.to === dstId;
      const isReverse = conn.to === srcId && conn.from === dstId;
      const allowed =
        direction === "both" ||
        (direction === "forward" && isForward) ||
        (direction === "reverse" && isReverse);
      const linkKey = `${conn.from}->${conn.to}`;

      if (!allowed) {
        dropPacket("direction-block", linkKey, true);
        return;
      }

      const conditions = { ...DEFAULT_LINK_CONDITIONS, ...(conn.conditions || {}) };
      if (conditions.blocked) {
        dropPacket("blocked", linkKey, true);
        return;
      }

      const lossPct = Math.max(0, Math.min(100, toNumber(conditions.lossPct, 0)));
      if (Math.random() * 100 < lossPct) {
        dropPacket(`loss ${lossPct}%`, linkKey, false);
        return;
      }

      const latencyMs = Math.max(0, toNumber(conditions.latencyMs, 0));
      const jitterMs = Math.max(0, toNumber(conditions.jitterMs, 0));
      const queueLimitPkts = Math.max(1, Math.trunc(toNumber(conditions.queueLimitPkts, 200)));
      const bandwidthPps = Math.max(1, toNumber(conditions.bandwidthPps, 100));
      const serviceIntervalMs = 1000 / bandwidthPps;
      const redEnabled = Boolean(conditions.redEnabled);
      const redMinThRaw = Math.max(0, Math.trunc(toNumber(conditions.redMinTh, 80)));
      const redMaxThRaw = Math.max(0, Math.trunc(toNumber(conditions.redMaxTh, 150)));
      const redMaxDropPct = Math.max(0, Math.min(100, toNumber(conditions.redMaxDropPct, 30)));
      const baseTime = toNumber(packet.time, 0);
      const arrivalMs = Math.max(0, Math.round(baseTime * 1000));

      const runtime = linkRuntimeRef.current[linkKey] || { queue: [] };
      runtime.queue = runtime.queue.filter((departureMs) => departureMs > arrivalMs);
      const queueDepth = runtime.queue.length;

      if (redEnabled) {
        const redMaxTh = Math.max(redMinThRaw + 1, redMaxThRaw);
        if (queueDepth >= redMinThRaw) {
          let redDropProb = redMaxDropPct;
          if (queueDepth < redMaxTh) {
            const ratio = (queueDepth - redMinThRaw) / (redMaxTh - redMinThRaw);
            redDropProb = ratio * redMaxDropPct;
          }
          if (Math.random() * 100 < redDropProb) {
            linkRuntimeRef.current[linkKey] = runtime;
            dropPacket(`red ${redDropProb.toFixed(1)}%`, linkKey, false, false, true);
            return;
          }
        }
      }

      if (runtime.queue.length >= queueLimitPkts) {
        linkRuntimeRef.current[linkKey] = runtime;
        dropPacket(`queue-full ${queueLimitPkts}`, linkKey, false, true);
        return;
      }

      const jitterOffset = jitterMs > 0 ? (Math.random() * 2 - 1) * jitterMs : 0;
      const effectiveLatencyMs = Math.max(0, latencyMs + jitterOffset);
      const headDeparture = runtime.queue.length > 0 ? runtime.queue[runtime.queue.length - 1] : arrivalMs;
      const departureMs = Math.max(arrivalMs, headDeparture) + serviceIntervalMs + effectiveLatencyMs;
      runtime.queue.push(departureMs);
      linkRuntimeRef.current[linkKey] = runtime;

      const delayedPacket = {
        ...packet,
        time: Number((departureMs / 1000).toFixed(4)),
      };

      deliveredPackets.push(delayedPacket);
      trafficIncrements.push({ srcId, dstId, isIpTraffic });
      linkIncrements.push({
        type: "flow",
        key: linkKey,
        direction: conn.from === srcId && conn.to === dstId ? "forward" : "reverse",
      });
      flights.push({
        id: `flight-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        linkKey,
        direction: conn.from === srcId && conn.to === dstId ? "forward" : "reverse",
        protocol: String(packet.protocol || "").toUpperCase(),
        fromId: srcId,
        toId: dstId,
        createdAt: Date.now(),
        durationMs: Math.max(1400, Math.min(4200, Math.round((effectiveLatencyMs + serviceIntervalMs + 700) * 2.2))),
      });
    });

    if (flights.length > 0) {
      setPacketFlights((prev) => [...prev, ...flights]);
      flights.forEach((flight) => {
        const timeoutId = setTimeout(() => {
          setPacketFlights((prev) => prev.filter((item) => item.id !== flight.id));
        }, flight.durationMs + 120);
        flightTimeoutsRef.current.push(timeoutId);
      });
    }

    setTrafficStats((prev) => {
      const next = { ...prev };

      trafficIncrements.forEach(({ srcId, dstId }) => {
        const prevSrc = next[srcId] || { inbound: 0, outbound: 0 };
        next[srcId] = { ...prevSrc, outbound: prevSrc.outbound + 1 };
        const prevDst = next[dstId] || { inbound: 0, outbound: 0 };
        next[dstId] = { ...prevDst, inbound: prevDst.inbound + 1 };
      });

      return next;
    });

    setIpTrafficStats((prev) => {
      const next = { ...prev };

      trafficIncrements.forEach(({ srcId, dstId, isIpTraffic }) => {
        if (!isIpTraffic) return;
        const prevSrc = next[srcId] || { inbound: 0, outbound: 0 };
        next[srcId] = { ...prevSrc, outbound: prevSrc.outbound + 1 };
        const prevDst = next[dstId] || { inbound: 0, outbound: 0 };
        next[dstId] = { ...prevDst, inbound: prevDst.inbound + 1 };
      });

      return next;
    });

    setLinkTrafficStats((prev) => {
      const next = { ...prev };

      linkIncrements.forEach((item) => {
        const prevLink = next[item.key] || {
          forward: 0,
          reverse: 0,
          dropped: 0,
          blocked: 0,
          queueDrops: 0,
          redDrops: 0,
        };
        if (item.type === "flow") {
          if (item.direction === "forward") {
            next[item.key] = { ...prevLink, forward: prevLink.forward + 1 };
          } else {
            next[item.key] = { ...prevLink, reverse: prevLink.reverse + 1 };
          }
        } else {
          next[item.key] = {
            ...prevLink,
            dropped: prevLink.dropped + 1,
            blocked: prevLink.blocked + (item.blocked ? 1 : 0),
            queueDrops: prevLink.queueDrops + (item.queue ? 1 : 0),
            redDrops: prevLink.redDrops + (item.red ? 1 : 0),
          };
        }
      });

      return next;
    });

    return { deliveredPackets, droppedPackets };
  }, [devices, connections]);

  const showCapturedPackets = useCallback(() => {
    setDisplayedPackets(capturedPackets);
  }, [capturedPackets]);

  return (
    <div className="app">
      <header className="app-header">
        <span className="app-logo">⬡</span>
        <h1 className="app-title">Network Lab</h1>
        <span className="app-subtitle">Interactive Network Simulator</span>
      </header>

      <div className="app-body">
        <div className="panel panel-canvas">
          <div className="panel-label">TOPOLOGY</div>
          <NetworkCanvas
            devices={devices}
            connections={connections}
            trafficStats={trafficStats}
            ipTrafficStats={ipTrafficStats}
            linkTrafficStats={linkTrafficStats}
            packetFlights={packetFlights}
            onAddDevice={addDevice}
            onUpdateDevice={updateDevice}
            onRemoveDevice={removeDevice}
            onAddConnection={addConnection}
            onUpdateConnection={updateConnection}
          />
        </div>
      </div>

      {/* Bottom panel toolbar */}
      <div className={`panel-bottom ${rightPanelOpen ? "expanded" : "collapsed"}`}>
        <button
          className="panel-bottom-toggle"
          onClick={() => setRightPanelOpen((prev) => !prev)}
          title={rightPanelOpen ? "Hide terminal & packet log" : "Show terminal & packet log"}
        >
          {rightPanelOpen ? "▲" : "▼"}
        </button>

        {rightPanelOpen && (
          <div className="panel-bottom-content">
            <div className="panel panel-terminal">
              <div className="panel-label">TERMINAL</div>
              <Terminal
                devices={devices}
                connections={connections}
                packets={capturedPackets}
                onAppendPackets={appendCapturedPackets}
                onClearPackets={clearCapturedPackets}
                onShowPackets={showCapturedPackets}
                onTrafficGenerated={applyTrafficPackets}
                onUpdateDevice={updateDevice}
              />
            </div>

            <div className="panel panel-packetlog">
              <div className="panel-label">PACKET LOG</div>
              <PacketLog packets={displayedPackets} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
