import React from "react";
import NetworkCanvas from "./NetworkCanvas";

export default function LiveNetworkCanvas({ devices }) {
  return (
    <div className="canvas-wrapper live-canvas-wrapper">
      <aside className="live-inventory-list" aria-label="Live inventory list">
        <h2>Discovered devices</h2>
        <p>{devices.length} shown · read-only</p>
        <ul>
          {devices.map((device) => (
            <li key={device.id}>
              <strong>{device.name}</strong>
              <span>{device.ip || "No current address"} · {device.status}</span>
            </li>
          ))}
        </ul>
      </aside>
      <NetworkCanvas
        devices={devices}
        connections={[]}
        trafficStats={{}}
        ipTrafficStats={{}}
        linkTrafficStats={{}}
        packetFlights={[]}
        readOnly
      />
    </div>
  );
}
