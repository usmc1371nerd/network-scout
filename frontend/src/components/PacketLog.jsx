
import React, { useState, useRef, useEffect } from "react";

const PROTO_CLASS = {
  ARP: "proto-arp",
  ICMP: "proto-icmp",
  TCP: "proto-tcp",
  UDP: "proto-udp",
  DNS: "proto-dns",
};

const COLS = [
  { key: "no",       label: "No.",       w: "52px"  },
  { key: "time",     label: "Time",      w: "80px"  },
  { key: "src",      label: "Source",    w: "160px" },
  { key: "dst",      label: "Destination", w: "160px" },
  { key: "protocol", label: "Protocol",  w: "84px"  },
  { key: "len",      label: "Len",       w: "52px"  },
  { key: "info",     label: "Info",      w: "auto"  },
];

export default function PacketLog({ packets }) {
  const [selected, setSelected] = useState(null);
  const tableBodyRef = useRef(null);

  useEffect(() => {
    if (tableBodyRef.current) {
      tableBodyRef.current.scrollTop = tableBodyRef.current.scrollHeight;
    }
  }, [packets]);

  const sel = selected !== null ? packets.find((p) => p.no === selected) : null;

  return (
    <div className="packetlog">
      {/* Table */}
      <div className="packetlog-table-wrap" ref={tableBodyRef}>
        <table className="packetlog-table">
          <thead>
            <tr>
              {COLS.map((c) => (
                <th key={c.key} style={{ width: c.w }}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {packets.length === 0 ? (
              <tr>
                <td colSpan={COLS.length} className="pkt-empty">
                  No packets captured — run a command in the terminal
                </td>
              </tr>
            ) : (
              packets.map((pkt) => (
                <tr
                  key={pkt.no}
                  className={`pkt-row ${PROTO_CLASS[pkt.protocol] || ""} ${
                    selected === pkt.no ? "pkt-selected" : ""
                  }`}
                  onClick={() =>
                    setSelected(selected === pkt.no ? null : pkt.no)
                  }
                >
                  <td>{pkt.no}</td>
                  <td>{typeof pkt.time === "number" ? pkt.time.toFixed(4) : pkt.time}</td>
                  <td className="pkt-addr">{pkt.src}</td>
                  <td className="pkt-addr">{pkt.dst}</td>
                  <td>
                    <span className={`proto-badge ${PROTO_CLASS[pkt.protocol] || ""}`}>
                      {pkt.protocol}
                    </span>
                  </td>
                  <td>{pkt.len}</td>
                  <td className="pkt-info">{pkt.info}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail pane */}
      {sel && (
        <div className="pkt-detail">
          <div className="pkt-detail-title">
            Frame {sel.no} — {sel.protocol}
          </div>
          <div className="pkt-detail-grid">
            {COLS.map((c) => (
              <React.Fragment key={c.key}>
                <span className="pkt-detail-key">{c.label}</span>
                <span className="pkt-detail-val">{String(sel[c.key] ?? "")}</span>
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      <div className="packetlog-status">
        {packets.length} packet{packets.length !== 1 ? "s" : ""} captured
      </div>
    </div>
  );
}
