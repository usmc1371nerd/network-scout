import React, { useEffect, useState } from "react";
import LiveNetworkCanvas from "./components/LiveNetworkCanvas";
import { fetchLiveInventory, sessionTokenFromHash } from "./liveInventory";

export default function LiveNetwork() {
  const [token] = useState(() => sessionTokenFromHash(window.location.hash));
  const [state, setState] = useState({ status: "loading", devices: [], message: "Loading discovered inventory…" });

  useEffect(() => {
    if (token) window.history.replaceState(null, "", window.location.pathname + window.location.search);
    const controller = new AbortController();
    fetchLiveInventory(token, { signal: controller.signal })
      .then((devices) => setState(devices.length
        ? { status: "ready", devices, message: "" }
        : { status: "empty", devices: [], message: "No discovered devices are stored yet. Passive observation will populate this view." }))
      .catch((error) => {
        if (error?.name !== "AbortError") setState({ status: error.kind || "unavailable", devices: [], message: error.message });
      });
    return () => controller.abort();
  }, [token]);

  return (
    <main className="live-network" data-mode="live">
      <div className="mode-banner live-mode-banner"><strong>Live Network</strong><span>Observed inventory · read-only</span></div>
      {state.status === "ready" ? <LiveNetworkCanvas devices={state.devices} /> : (
        <section className={`live-state live-state-${state.status}`} role={state.status === "loading" ? "status" : "alert"}>
          <h2>{state.status === "loading" ? "Loading live inventory" : state.status === "empty" ? "No devices discovered" : state.status === "authentication" ? "Authentication required" : "Backend unavailable"}</h2>
          <p>{state.message}</p>
        </section>
      )}
    </main>
  );
}
