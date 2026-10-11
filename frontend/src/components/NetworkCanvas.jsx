
import React, { useState, useRef, useEffect } from "react";
import {
  getConnectionSecurityInsights,
  getDeviceSecurityInsights,
} from "../securityInsights";

const DEVICE_ICONS = {
  pc: "💻",
  server: "🖥️",
  router: "📡",
  switch: "🔀",
  phone: "📱",
  laptop: "💼",
  beacon: "📶",
  sensor: "🌡️",
  gateway: "🛰️",
  "iot-bulb": "💡",
  "iot-lock": "🔒",
  "iot-tag": "🏷️",
  "iot-camera": "📷",
  "iot-thermostat": "🌡️",
  "iot-plug": "🔌",
  "usb-storage": "💾",
  "usb-keyboard": "⌨️",
  "usb-mouse": "🖱️",
  "usb-webcam": "📹",
  "usb-audio": "🎧",
  "usb-printer": "🖨️",
};
const DEVICE_LABELS = {
  pc: "PC",
  server: "Server",
  router: "Router",
  switch: "Switch",
  phone: "Phone",
  laptop: "Laptop",
  beacon: "BLE Beacon",
  sensor: "BLE Sensor",
  gateway: "BT Gateway",
  "iot-bulb": "IoT Bulb",
  "iot-lock": "IoT Lock",
  "iot-tag": "IoT Tag",
  "iot-camera": "IoT Camera",
  "iot-thermostat": "IoT Thermostat",
  "iot-plug": "IoT Plug",
  "usb-storage": "Removable Storage",
  "usb-keyboard": "Keyboard",
  "usb-mouse": "Mouse",
  "usb-webcam": "Webcam",
  "usb-audio": "Audio",
  "usb-printer": "Printer",
};
const PALETTE_GROUPS = [
  {
    title: "Core",
    devices: ["pc", "server", "router", "switch"],
  },
  {
    title: "Bluetooth",
    devices: ["phone", "laptop", "beacon", "sensor", "gateway"],
  },
  {
    title: "IoT",
    devices: ["iot-bulb", "iot-lock", "iot-tag", "iot-camera", "iot-thermostat", "iot-plug"],
  },
  {
    title: "Other Devices",
    devices: ["usb-storage", "usb-keyboard", "usb-mouse", "usb-webcam", "usb-audio", "usb-printer"],
  },
];
const NODE_W = 136;
const NODE_H = 68;
const USB_PERIPHERAL_TYPES = new Set([
  "usb-storage",
  "usb-keyboard",
  "usb-mouse",
  "usb-webcam",
  "usb-audio",
  "usb-printer",
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
const BLUETOOTH_TYPES = new Set([
  "phone",
  "laptop",
  "beacon",
  "sensor",
  "gateway",
  "iot-bulb",
  "iot-lock",
  "iot-tag",
  "iot-camera",
  "iot-thermostat",
  "iot-plug",
]);

const normalizeTransport = (transport) => {
  const normalized = String(transport || "").toLowerCase();
  if (normalized === "network") return "cat";
  if (normalized === "cat" || normalized === "wifi" || normalized === "usb" || normalized === "bluetooth") {
    return normalized;
  }
  return "cat";
};

export default function NetworkCanvas({
  devices,
  connections,
  trafficStats,
  ipTrafficStats,
  linkTrafficStats,
  packetFlights,
  onAddDevice,
  onUpdateDevice,
  onRemoveDevice,
  onAddConnection,
  onUpdateConnection,
}) {
  const canvasRef = useRef(null);
  const draggingRef = useRef(null);
  const panRef = useRef(null);

  const [connectMode, setConnectMode] = useState(false);
  const [connectSource, setConnectSource] = useState(null);
  const [connectDirection, setConnectDirection] = useState("both");
  const [connectTransport, setConnectTransport] = useState("auto");
  const [editingId, setEditingId] = useState(null);
  const [editIpValue, setEditIpValue] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState({});
  const [selectedConnectionKey, setSelectedConnectionKey] = useState(null);
  const [advancedLinkControls, setAdvancedLinkControls] = useState(false);
  const [linkPreset, setLinkPreset] = useState("stable");
  const [clockMs, setClockMs] = useState(Date.now());
  const [securityInspector, setSecurityInspector] = useState(null);
  const [canvasScale, setCanvasScale] = useState(1);
  const [canvasPan, setCanvasPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);

  const toWorldCoords = (clientX, clientY) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0, rect: null };
    return {
      x: (clientX - rect.left - canvasPan.x) / canvasScale,
      y: (clientY - rect.top - canvasPan.y) / canvasScale,
      rect,
    };
  };

  useEffect(() => {
    const timer = setInterval(() => setClockMs(Date.now()), 40);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!securityInspector) return;

    if (securityInspector.type === "device") {
      const exists = devices.some((device) => device.id === securityInspector.deviceId);
      if (!exists) setSecurityInspector(null);
      return;
    }

    if (securityInspector.type === "connection") {
      const exists = connections.some(
        (conn) => `${conn.from}->${conn.to}` === securityInspector.connectionKey
      );
      if (!exists) setSecurityInspector(null);
    }
  }, [securityInspector, devices, connections]);

  /* ── palette drag ─────────────────────────────────────────── */
  const onPaletteDragStart = (e, type) => {
    e.dataTransfer.setData("deviceType", type);
  };

  /* ── canvas drop ──────────────────────────────────────────── */
  const onCanvasDrop = (e) => {
    e.preventDefault();
    const type = e.dataTransfer.getData("deviceType");
    if (!type) return;
    const world = toWorldCoords(e.clientX, e.clientY);
    const x = world.x - NODE_W / 2;
    const y = world.y - NODE_H / 2;
    onAddDevice(type, x, y);
  };

  /* ── device drag within canvas ────────────────────────────── */
  const onDeviceMouseDown = (e, device) => {
    if (connectMode) return;
    if (e.target.tagName === "INPUT" || e.target.tagName === "BUTTON") return;
    e.stopPropagation();
    const world = toWorldCoords(e.clientX, e.clientY);
    draggingRef.current = {
      id: device.id,
      offsetX: world.x - device.x,
      offsetY: world.y - device.y,
    };
  };

  const onCanvasMouseMove = (e) => {
    if (isPanning) {
      onCanvasPan(e);
      return;
    }
    if (!draggingRef.current) return;
    const world = toWorldCoords(e.clientX, e.clientY);
    const x = world.x - draggingRef.current.offsetX;
    const y = world.y - draggingRef.current.offsetY;
    onUpdateDevice(draggingRef.current.id, { x, y });
  };

  const onCanvasMouseUp = () => {
    draggingRef.current = null;
    panRef.current = null;
    setIsPanning(false);
  };

  /* ── canvas zoom & pan ────────────────────────────────────── */
  const onCanvasWheel = (e) => {
    if (!e.ctrlKey && !e.metaKey) return; // Only zoom with Ctrl/Cmd held
    e.preventDefault();
    const direction = e.deltaY > 0 ? -1 : 1; // Scroll down = zoom out, scroll up = zoom in
    const zoomStep = 0.1;
    const newScale = Math.max(0.3, Math.min(3, canvasScale + direction * zoomStep));
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) {
      setCanvasScale(newScale);
      return;
    }

    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const worldX = (mouseX - canvasPan.x) / canvasScale;
    const worldY = (mouseY - canvasPan.y) / canvasScale;
    const nextPan = {
      x: mouseX - worldX * newScale,
      y: mouseY - worldY * newScale,
    };

    setCanvasScale(newScale);
    setCanvasPan(nextPan);
  };

  const onCanvasKeyDown = (e) => {
    if (e.code === "Space") {
      e.preventDefault();
      if (!isPanning) {
        setIsPanning(true);
        panRef.current = null;
      }
    }
  };

  const onCanvasKeyUp = (e) => {
    if (e.code === "Space") {
      setIsPanning(false);
      panRef.current = null;
    }
  };

  const onCanvasPan = (e) => {
    if (!isPanning) return;
    if (!panRef.current) {
      panRef.current = {
        panStartX: e.clientX,
        panStartY: e.clientY,
        panInitialX: canvasPan.x,
        panInitialY: canvasPan.y,
      };
    }
    const deltaX = e.clientX - panRef.current.panStartX;
    const deltaY = e.clientY - panRef.current.panStartY;
    setCanvasPan({
      x: panRef.current.panInitialX + deltaX,
      y: panRef.current.panInitialY + deltaY,
    });
  };

  /* ── device click ─────────────────────────────────────────── */
  const onDeviceClick = (e, device) => {
    e.stopPropagation();
    if (connectMode) {
      if (!connectSource) {
        setConnectSource(device.id);
      } else if (connectSource !== device.id) {
        const sourceDevice = devices.find((item) => item.id === connectSource);
        const preferredTransport = connectTransport;
        const resolvedTransport =
          preferredTransport !== "auto"
            ? preferredTransport
            : sourceDevice && device
              ? USB_PERIPHERAL_TYPES.has(sourceDevice.type) || USB_PERIPHERAL_TYPES.has(device.type)
                ? "usb"
                : BLUETOOTH_TYPES.has(sourceDevice.type) || BLUETOOTH_TYPES.has(device.type)
                  ? "bluetooth"
                  : "cat"
              : "cat";

        onAddConnection(connectSource, device.id, connectDirection, resolvedTransport);
        setConnectSource(null);
        setConnectMode(false);
      }
      return;
    }
    if (NON_IP_CAPABLE_TYPES.has(device.type)) {
      setEditingId(null);
      return;
    }
    setEditingId(device.id);
    setEditIpValue(device.ip || "");
  };

  const commitIp = (id) => {
    const targetDevice = devices.find((device) => device.id === id);
    if (!targetDevice || NON_IP_CAPABLE_TYPES.has(targetDevice.type)) {
      setEditingId(null);
      return;
    }
    onUpdateDevice(id, { ip: editIpValue.trim() });
    setEditingId(null);
  };

  const cancelConnect = () => {
    setConnectMode(false);
    setConnectSource(null);
  };

  const center = (d) => ({ cx: d.x + NODE_W / 2, cy: d.y + NODE_H / 2 });

  const pointOnQuadratic = (startPoint, controlPoint, endPoint, t) => {
    const oneMinusT = 1 - t;
    const x =
      oneMinusT * oneMinusT * startPoint.cx +
      2 * oneMinusT * t * controlPoint.x +
      t * t * endPoint.cx;
    const y =
      oneMinusT * oneMinusT * startPoint.cy +
      2 * oneMinusT * t * controlPoint.y +
      t * t * endPoint.cy;
    return { x, y };
  };

  const toggleGroup = (title) => {
    setCollapsedGroups((prev) => ({
      ...prev,
      [title]: !prev[title],
    }));
  };

  const collapseAllGroups = () => {
    const allCollapsed = {};
    PALETTE_GROUPS.forEach((group) => {
      allCollapsed[group.title] = true;
    });
    setCollapsedGroups(allCollapsed);
  };

  const expandAllGroups = () => {
    setCollapsedGroups({});
  };

  const selectedConnection =
    connections.find((conn) => `${conn.from}->${conn.to}` === selectedConnectionKey) || null;

  const inspectedDevice = securityInspector?.type === "device"
    ? devices.find((device) => device.id === securityInspector.deviceId) || null
    : null;
  const inspectedConnection = securityInspector?.type === "connection"
    ? connections.find((conn) => `${conn.from}->${conn.to}` === securityInspector.connectionKey) || null
    : null;
  const securityFindings = inspectedDevice
    ? getDeviceSecurityInsights(inspectedDevice, devices, connections)
    : inspectedConnection
      ? getConnectionSecurityInsights(inspectedConnection, devices, connections)
      : [];
  const securityTitle = inspectedDevice
    ? inspectedDevice.name
    : inspectedConnection
      ? `${devices.find((device) => device.id === inspectedConnection.from)?.name || inspectedConnection.from} ↔ ${devices.find((device) => device.id === inspectedConnection.to)?.name || inspectedConnection.to}`
      : "Security insight";
  const securitySubtitle = inspectedDevice
    ? "Device-level educational concerns"
    : inspectedConnection
      ? "Link-level educational concerns"
      : "";

  const selectedSource = selectedConnection
    ? devices.find((device) => device.id === selectedConnection.from)
    : null;
  const selectedTarget = selectedConnection
    ? devices.find((device) => device.id === selectedConnection.to)
    : null;

  const selectedConditions = {
    lossPct: selectedConnection?.conditions?.lossPct ?? 0,
    latencyMs: selectedConnection?.conditions?.latencyMs ?? 0,
    jitterMs: selectedConnection?.conditions?.jitterMs ?? 0,
    queueLimitPkts: selectedConnection?.conditions?.queueLimitPkts ?? 200,
    bandwidthPps: selectedConnection?.conditions?.bandwidthPps ?? 100,
    redEnabled: selectedConnection?.conditions?.redEnabled ?? false,
    redMinTh: selectedConnection?.conditions?.redMinTh ?? 80,
    redMaxTh: selectedConnection?.conditions?.redMaxTh ?? 150,
    redMaxDropPct: selectedConnection?.conditions?.redMaxDropPct ?? 30,
    blocked: selectedConnection?.conditions?.blocked ?? false,
  };
  const selectedTransport = normalizeTransport(selectedConnection?.transport || "cat");

  const updateSelectedConditions = (fields) => {
    if (!selectedConnection) return;
    onUpdateConnection?.(selectedConnection.from, selectedConnection.to, {
      conditions: {
        ...selectedConditions,
        ...fields,
      },
    });
  };

  const applyPresetToSelectedLink = () => {
    if (!selectedConnection) return;
    const presetMap = {
      stable: {
        lossPct: 0,
        latencyMs: 10,
        jitterMs: 2,
        queueLimitPkts: 200,
        bandwidthPps: 1000,
        redEnabled: false,
        redMinTh: 80,
        redMaxTh: 150,
        redMaxDropPct: 30,
        blocked: false,
      },
      congested: {
        lossPct: 2,
        latencyMs: 120,
        jitterMs: 30,
        queueLimitPkts: 40,
        bandwidthPps: 20,
        redEnabled: true,
        redMinTh: 15,
        redMaxTh: 35,
        redMaxDropPct: 35,
        blocked: false,
      },
      hostile: {
        lossPct: 15,
        latencyMs: 260,
        jitterMs: 90,
        queueLimitPkts: 20,
        bandwidthPps: 8,
        redEnabled: true,
        redMinTh: 5,
        redMaxTh: 15,
        redMaxDropPct: 75,
        blocked: false,
      },
    };

    const preset = presetMap[linkPreset] || presetMap.stable;
    updateSelectedConditions(preset);
  };

  return (
    <div className="canvas-wrapper">
      {/* ── Palette ── */}
      <div className="palette">
        <div className="palette-title">Devices</div>
        <div className="palette-actions">
          <button className="palette-action-btn" onClick={expandAllGroups}>
            Expand all
          </button>
          <button className="palette-action-btn" onClick={collapseAllGroups}>
            Collapse all
          </button>
        </div>
        {PALETTE_GROUPS.map((group) => (
          <div key={group.title} className="palette-group">
            <button
              className="palette-group-toggle"
              onClick={() => toggleGroup(group.title)}
              title={collapsedGroups[group.title] ? "Expand section" : "Collapse section"}
            >
              <span className="palette-group-arrow">
                {collapsedGroups[group.title] ? "▸" : "▾"}
              </span>
              <span className="palette-group-title">{group.title}</span>
            </button>

            {!collapsedGroups[group.title] && group.devices.map((type) => (
              <div
                key={type}
                className="palette-item"
                draggable
                onDragStart={(e) => onPaletteDragStart(e, type)}
              >
                <span className="palette-icon">{DEVICE_ICONS[type]}</span>
                <span className="palette-name">
                  {DEVICE_LABELS[type] || type}
                </span>
              </div>
            ))}
          </div>
        ))}
        <hr className="palette-divider" />
        <button
          className={`btn-connect ${connectMode ? "active" : ""}`}
          onClick={() => (connectMode ? cancelConnect() : setConnectMode(true))}
        >
          {connectMode
            ? connectSource
              ? "▸ Pick target…"
              : "▸ Pick source…"
            : "⬡ Connect"}
        </button>
        {connectMode && (
          <>
            <div className="connect-dir-row">
              <button
                className={`connect-dir ${connectDirection === "both" ? "active" : ""}`}
                onClick={() => setConnectDirection("both")}
              >
                ↔
              </button>
              <button
                className={`connect-dir ${connectDirection === "forward" ? "active" : ""}`}
                onClick={() => setConnectDirection("forward")}
              >
                →
              </button>
              <button
                className={`connect-dir ${connectDirection === "reverse" ? "active" : ""}`}
                onClick={() => setConnectDirection("reverse")}
              >
                ←
              </button>
            </div>
            <div className="connect-dir-hint">
              {connectDirection === "both" && "Bi-directional"}
              {connectDirection === "forward" && "Outbound (source → target)"}
              {connectDirection === "reverse" && "Inbound (target → source)"}
            </div>
            <div className="connect-transport-row">
              <label className="connect-transport-label" htmlFor="connect-transport">
                Link type
              </label>
              <select
                id="connect-transport"
                className="connect-transport-select"
                value={connectTransport}
                onChange={(e) => setConnectTransport(e.target.value)}
              >
                <option value="auto">Auto</option>
                <option value="cat">CAT (Ethernet)</option>
                <option value="wifi">WiFi</option>
                <option value="usb">USB</option>
                <option value="bluetooth">Bluetooth</option>
              </select>
            </div>
            <button className="btn-cancel" onClick={cancelConnect}>
              Cancel
            </button>
          </>
        )}

        <hr className="palette-divider" />
        <div className="link-editor">
          <div className="link-editor-title">Link</div>
          {!selectedConnection ? (
            <div className="link-editor-empty">Click a connection to edit.</div>
          ) : (
            <>
              <div className="link-editor-name">
                {selectedSource?.name || selectedConnection.from} → {selectedTarget?.name || selectedConnection.to}
              </div>
              <div className="link-editor-row">
                <select
                  className="link-editor-select"
                  value={linkPreset}
                  onChange={(e) => setLinkPreset(e.target.value)}
                >
                  <option value="stable">Stable</option>
                  <option value="congested">Congested</option>
                  <option value="hostile">Hostile</option>
                </select>
                <button className="link-editor-apply" onClick={applyPresetToSelectedLink}>
                  Apply
                </button>
              </div>
              <label className="link-editor-field">
                <span>Connection type</span>
                <select
                  className="link-editor-select"
                  value={selectedTransport}
                  onChange={(e) => onUpdateConnection?.(selectedConnection.from, selectedConnection.to, {
                    transport: e.target.value,
                  })}
                >
                  <option value="cat">CAT (Ethernet)</option>
                  <option value="wifi">WiFi</option>
                  <option value="usb">USB</option>
                  <option value="bluetooth">Bluetooth</option>
                </select>
              </label>
              <label className="link-editor-field">
                <span>Loss %</span>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={selectedConditions.lossPct}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    updateSelectedConditions({
                      lossPct: Number.isFinite(next) ? Math.max(0, Math.min(100, next)) : 0,
                    });
                  }}
                />
              </label>
              <label className="link-editor-field">
                <span>Latency ms</span>
                <input
                  type="number"
                  min="0"
                  max="5000"
                  value={selectedConditions.latencyMs}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    updateSelectedConditions({
                      latencyMs: Number.isFinite(next) ? Math.max(0, Math.min(5000, next)) : 0,
                    });
                  }}
                />
              </label>
              <button
                className="link-editor-toggle"
                onClick={() => setAdvancedLinkControls((prev) => !prev)}
              >
                {advancedLinkControls ? "Hide advanced" : "Show advanced"}
              </button>
              {advancedLinkControls && (
                <>
              <label className="link-editor-field">
                <span>Jitter ms (±)</span>
                <input
                  type="number"
                  min="0"
                  max="2000"
                  value={selectedConditions.jitterMs}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    updateSelectedConditions({
                      jitterMs: Number.isFinite(next) ? Math.max(0, Math.min(2000, next)) : 0,
                    });
                  }}
                />
              </label>
              <label className="link-editor-field">
                <span>Queue capacity (pkts)</span>
                <input
                  type="number"
                  min="1"
                  max="10000"
                  value={selectedConditions.queueLimitPkts}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    updateSelectedConditions({
                      queueLimitPkts: Number.isFinite(next) ? Math.max(1, Math.min(10000, Math.trunc(next))) : 200,
                    });
                  }}
                />
              </label>
              <label className="link-editor-field">
                <span>Bandwidth (pps)</span>
                <input
                  type="number"
                  min="1"
                  max="100000"
                  value={selectedConditions.bandwidthPps}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    updateSelectedConditions({
                      bandwidthPps: Number.isFinite(next) ? Math.max(1, Math.min(100000, Math.trunc(next))) : 100,
                    });
                  }}
                />
              </label>
              <label className="link-editor-check">
                <input
                  type="checkbox"
                  checked={selectedConditions.redEnabled}
                  onChange={(e) => updateSelectedConditions({ redEnabled: e.target.checked })}
                />
                <span>RED early drop</span>
              </label>
              {selectedConditions.redEnabled && (
                <>
                  <label className="link-editor-field">
                    <span>RED min threshold</span>
                    <input
                      type="number"
                      min="0"
                      max="10000"
                      value={selectedConditions.redMinTh}
                      onChange={(e) => {
                        const next = Number(e.target.value);
                        updateSelectedConditions({
                          redMinTh: Number.isFinite(next) ? Math.max(0, Math.min(10000, Math.trunc(next))) : 80,
                        });
                      }}
                    />
                  </label>
                  <label className="link-editor-field">
                    <span>RED max threshold</span>
                    <input
                      type="number"
                      min="1"
                      max="10000"
                      value={selectedConditions.redMaxTh}
                      onChange={(e) => {
                        const next = Number(e.target.value);
                        updateSelectedConditions({
                          redMaxTh: Number.isFinite(next) ? Math.max(1, Math.min(10000, Math.trunc(next))) : 150,
                        });
                      }}
                    />
                  </label>
                  <label className="link-editor-field">
                    <span>RED max drop %</span>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      value={selectedConditions.redMaxDropPct}
                      onChange={(e) => {
                        const next = Number(e.target.value);
                        updateSelectedConditions({
                          redMaxDropPct: Number.isFinite(next) ? Math.max(0, Math.min(100, next)) : 30,
                        });
                      }}
                    />
                  </label>
                </>
              )}
              </>
              )}
              <label className="link-editor-check">
                <input
                  type="checkbox"
                  checked={selectedConditions.blocked}
                  onChange={(e) => updateSelectedConditions({ blocked: e.target.checked })}
                />
                <span>Blocked</span>
              </label>
            </>
          )}
        </div>
      </div>

      {/* ── Canvas ── */}
      <div
        ref={canvasRef}
        className={`canvas-area ${connectMode ? "connect-mode" : ""} ${isPanning ? "panning" : ""}`}
        onDrop={onCanvasDrop}
        onDragOver={(e) => e.preventDefault()}
        onMouseMove={onCanvasMouseMove}
        onMouseUp={onCanvasMouseUp}
        onMouseLeave={onCanvasMouseUp}
        onWheel={onCanvasWheel}
        onKeyDown={onCanvasKeyDown}
        onKeyUp={onCanvasKeyUp}
        tabIndex={0}
        onClick={() => {
          setEditingId(null);
          setSelectedConnectionKey(null);
        }}
      >
        <div
          className="canvas-world"
          style={{
            transform: `translate(${canvasPan.x}px, ${canvasPan.y}px) scale(${canvasScale})`,
            transformOrigin: "0 0",
            transition: isPanning ? "none" : "transform 0.05s ease-out",
          }}
        >
        {/* SVG connection lines */}
        <svg
          style={{
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            pointerEvents: "auto",
            overflow: "visible",
          }}
        >
          <defs>
          </defs>
          {connections.map((conn, i) => {
            const src = devices.find((d) => d.id === conn.from);
            const dst = devices.find((d) => d.id === conn.to);
            if (!src || !dst) return null;
            const s = center(src);
            const t = center(dst);
            const m = { x: (s.cx + t.cx) / 2, y: (s.cy + t.cy) / 2 };
            const linkKey = `${conn.from}->${conn.to}`;
            const linkFlow = linkTrafficStats?.[linkKey] || {
              forward: 0,
              reverse: 0,
              dropped: 0,
              blocked: 0,
              queueDrops: 0,
              redDrops: 0,
            };
            const direction = conn.direction || "both";
            const conditions = conn.conditions || {};
            const transportValue = normalizeTransport(conn.transport || "cat");
            const transportClass = `transport-${transportValue}`;
            const transportLabel = {
              cat: "CAT",
              wifi: "WIFI",
              usb: "USB",
              bluetooth: "BLUETOOTH",
            }[transportValue] || "CAT";
            const conditionLabel = `${transportLabel} · ${conditions.lossPct || 0}% · ${conditions.latencyMs || 0}±${conditions.jitterMs || 0}ms · bw${conditions.bandwidthPps || 100}pps · q${conditions.queueLimitPkts || 200}${conditions.redEnabled ? " · RED" : ""}${conditions.blocked ? " · BLOCK" : ""}`;
            const isSelected = selectedConnectionKey === linkKey;

            const dx = t.cx - s.cx;
            const dy = t.cy - s.cy;
            const len = Math.hypot(dx, dy) || 1;
            const nx = -dy / len;
            const ny = dx / len;
            const bend = 26;
            const topCtrl = { x: m.x + nx * bend, y: m.y + ny * bend };
            const bottomCtrl = { x: m.x - nx * bend, y: m.y - ny * bend };

            const inboundBadge = {
              x: t.cx + nx * 10,
              y: t.cy + ny * 10,
            };
            const outboundBadge = {
              x: s.cx - nx * 10,
              y: s.cy - ny * 10,
            };

            const inboundPath = `M ${s.cx} ${s.cy} Q ${topCtrl.x} ${topCtrl.y} ${t.cx} ${t.cy}`;
            const outboundPath = `M ${s.cx} ${s.cy} Q ${bottomCtrl.x} ${bottomCtrl.y} ${t.cx} ${t.cy}`;
            const linkFlights = (packetFlights || []).filter((flight) => flight.linkKey === linkKey);

            const inboundMuted = direction === "forward";
            const outboundMuted = direction === "reverse";

            return (
              <g key={i}>
                <path
                  d={inboundPath}
                  className={`conn-hit${isSelected ? " selected" : ""}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedConnectionKey(linkKey);
                  }}
                />
                <path
                  d={outboundPath}
                  className={`conn-hit${isSelected ? " selected" : ""}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedConnectionKey(linkKey);
                  }}
                />
                <path d={inboundPath} className={`conn-path conn-inbound ${transportClass}${inboundMuted ? " muted" : ""}${isSelected ? " selected" : ""}`} />
                <path d={outboundPath} className={`conn-path conn-outbound ${transportClass}${outboundMuted ? " muted" : ""}${isSelected ? " selected" : ""}`} />

                <g
                  className="conn-info-button"
                  transform={`translate(${m.x}, ${m.y - 22})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedConnectionKey(linkKey);
                    setSecurityInspector({ type: "connection", connectionKey: linkKey });
                  }}
                >
                  <circle r="9" className="conn-info-circle" />
                  <text y="1" textAnchor="middle" className="conn-info-text">i</text>
                </g>

                <text x={topCtrl.x} y={topCtrl.y - 8} textAnchor="middle" className="conn-label-in">
                  Inbound
                </text>
                <text x={bottomCtrl.x} y={bottomCtrl.y + 14} textAnchor="middle" className="conn-label-out">
                  Outbound
                </text>
                <text x={m.x} y={m.y + 4} textAnchor="middle" className={`conn-conditions${conditions.blocked ? " blocked" : ""}`}>
                  {conditionLabel}
                </text>

                <g transform={`translate(${inboundBadge.x}, ${inboundBadge.y})`}>
                  <rect x="-12" y="-9" width="24" height="14" rx="4" className="conn-badge-in" />
                  <text x="0" y="1" textAnchor="middle" className="conn-badge-text">{linkFlow.reverse}</text>
                </g>

                <g transform={`translate(${outboundBadge.x}, ${outboundBadge.y})`}>
                  <rect x="-12" y="-9" width="24" height="14" rx="4" className="conn-badge-out" />
                  <text x="0" y="1" textAnchor="middle" className="conn-badge-text">{linkFlow.forward}</text>
                </g>

                {linkFlow.dropped > 0 && (
                  <g transform={`translate(${m.x}, ${m.y - 12})`}>
                    <rect x="-18" y="-9" width="36" height="14" rx="4" className="conn-badge-drop" />
                    <text x="0" y="1" textAnchor="middle" className="conn-badge-text">-{linkFlow.dropped}</text>
                  </g>
                )}

                {linkFlow.queueDrops > 0 && (
                  <g transform={`translate(${m.x}, ${m.y + 16})`}>
                    <rect x="-20" y="-9" width="40" height="14" rx="4" className="conn-badge-queue" />
                    <text x="0" y="1" textAnchor="middle" className="conn-badge-text">q-{linkFlow.queueDrops}</text>
                  </g>
                )}

                {linkFlow.redDrops > 0 && (
                  <g transform={`translate(${m.x}, ${m.y + 32})`}>
                    <rect x="-18" y="-9" width="36" height="14" rx="4" className="conn-badge-red" />
                    <text x="0" y="1" textAnchor="middle" className="conn-badge-text">r-{linkFlow.redDrops}</text>
                  </g>
                )}

                {linkFlights.map((flight) => {
                  const usesOutboundPath = flight.direction === "forward";
                  const isReverseFlight = flight.direction === "reverse";
                  const startPoint = isReverseFlight ? t : s;
                  const endPoint = isReverseFlight ? s : t;
                  const controlPoint = usesOutboundPath ? bottomCtrl : topCtrl;
                  const elapsed = Math.max(0, clockMs - (flight.createdAt || clockMs));
                  const duration = Math.max(400, flight.durationMs || 1200);
                  const progress = Math.min(1, elapsed / duration);
                  const position = pointOnQuadratic(startPoint, controlPoint, endPoint, progress);
                  return (
                    <circle
                      key={flight.id}
                      cx={position.x}
                      cy={position.y}
                      r="4.2"
                      className={`packet-flight-dot ${usesOutboundPath ? "outbound" : "inbound"}`}
                    />
                  );
                })}
              </g>
            );
          })}
        </svg>

        {/* Device nodes */}
        {devices.map((device) => (
          <div
            key={device.id}
            className={`device-node device-${device.type}${
              connectSource === device.id ? " connect-source" : ""
            }`}
            style={{ left: device.x, top: device.y, width: NODE_W, height: NODE_H }}
            onMouseDown={(e) => onDeviceMouseDown(e, device)}
            onClick={(e) => onDeviceClick(e, device)}
          >
            <button
              className="device-delete"
              title="Remove device"
              onClick={(e) => {
                e.stopPropagation();
                onRemoveDevice(device.id);
              }}
            >
              ×
            </button>
            <button
              className="device-insight"
              title="View security insight"
              onClick={(e) => {
                e.stopPropagation();
                setSecurityInspector({ type: "device", deviceId: device.id });
              }}
            >
              i
            </button>
            <span className="device-icon">{DEVICE_ICONS[device.type]}</span>
            <div className="device-info">
              <div className="device-name">{device.name}</div>
              {!NON_IP_CAPABLE_TYPES.has(device.type) && (
                <>
                  <div className="device-traffic">
                    <span className="traffic-label">DEV</span>
                    <span className="traffic-out">↑ {(trafficStats?.[device.id]?.outbound) || 0}</span>
                    <span className="traffic-in">↓ {(trafficStats?.[device.id]?.inbound) || 0}</span>
                  </div>
                  <div className="device-traffic device-traffic-ip">
                    <span className="traffic-label">IP</span>
                    <span className="traffic-out">↑ {(ipTrafficStats?.[device.id]?.outbound) || 0}</span>
                    <span className="traffic-in">↓ {(ipTrafficStats?.[device.id]?.inbound) || 0}</span>
                  </div>
                </>
              )}
              {NON_IP_CAPABLE_TYPES.has(device.type) ? (
                <div className="device-ip" title="Peripheral endpoint (no IP)">
                  <span className="ip-placeholder">non-IP peripheral</span>
                </div>
              ) : editingId === device.id ? (
                <div
                  className="ip-edit"
                  onClick={(e) => e.stopPropagation()}
                >
                  <input
                    autoFocus
                    className="ip-input"
                    value={editIpValue}
                    placeholder="192.168.1.x"
                    onChange={(e) => setEditIpValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitIp(device.id);
                      if (e.key === "Escape") setEditingId(null);
                    }}
                  />
                  <button className="ip-save" onClick={() => commitIp(device.id)}>
                    ✓
                  </button>
                </div>
              ) : (
                <div className="device-ip" title="Click to assign IP">
                  {device.ip || (
                    <span className="ip-placeholder">set IP…</span>
                  )}
                </div>
              )}
              {!NON_IP_CAPABLE_TYPES.has(device.type) && device.type !== "switch" && (
                <div className="device-meta" title="Layer-2 / ARP cache summary">
                  <span className="device-meta-item">MAC: {device.mac || "unassigned"}</span>
                  <span className="device-meta-item">ARP entries: {Object.keys(device.arp_table || {}).length}</span>
                </div>
              )}
            </div>
          </div>
        ))}

        </div>

        <div className="canvas-start-hint">
          <span>← Drag a device onto the canvas to begin</span>
        </div>

        {/* Zoom/Pan hints */}
        <div className="canvas-controls-hint">
          <span>Ctrl+Scroll to zoom • Space+Drag to pan</span>
        </div>

        {securityInspector && (
          <div
            className="security-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="security-panel-header">
              <div>
                <div className="security-panel-title">{securityTitle}</div>
                <div className="security-panel-subtitle">{securitySubtitle}</div>
              </div>
              <button
                className="security-panel-close"
                onClick={() => setSecurityInspector(null)}
                title="Close security insights"
              >
                ×
              </button>
            </div>

            <div className="security-panel-note">
              Topology-based guidance only. These findings are educational hints, not live scanning results.
            </div>

            <div className="security-findings">
              {securityFindings.map((finding) => (
                <div key={`${finding.severity}-${finding.title}`} className="security-finding">
                  <div className="security-finding-header">
                    <span className={`security-severity severity-${finding.severity}`}>{finding.severity}</span>
                    <span className="security-finding-title">{finding.title}</span>
                  </div>
                  <div className="security-finding-summary">{finding.summary}</div>
                  <div className="security-finding-recommendation">{finding.recommendation}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
