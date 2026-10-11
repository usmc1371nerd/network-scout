export function fitDevicesToViewport(devices, viewportWidth, viewportHeight, {
  nodeWidth = 136,
  nodeHeight = 68,
  padding = 36,
} = {}) {
  if (!Array.isArray(devices) || devices.length === 0 || viewportWidth <= 0 || viewportHeight <= 0) {
    return { scale: 1, pan: { x: 0, y: 0 } };
  }

  const minX = Math.min(...devices.map((device) => Number(device.x) || 0));
  const minY = Math.min(...devices.map((device) => Number(device.y) || 0));
  const maxX = Math.max(...devices.map((device) => (Number(device.x) || 0) + nodeWidth));
  const maxY = Math.max(...devices.map((device) => (Number(device.y) || 0) + nodeHeight));
  const contentWidth = Math.max(1, maxX - minX);
  const contentHeight = Math.max(1, maxY - minY);
  const availableWidth = Math.max(1, viewportWidth - padding * 2);
  const availableHeight = Math.max(1, viewportHeight - padding * 2);
  const scale = Math.min(1, availableWidth / contentWidth, availableHeight / contentHeight);

  return {
    scale,
    pan: {
      x: (viewportWidth - contentWidth * scale) / 2 - minX * scale,
      y: (viewportHeight - contentHeight * scale) / 2 - minY * scale,
    },
  };
}
