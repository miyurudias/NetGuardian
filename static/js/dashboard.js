/* NetGuard - Modern Dashboard Controller & Real Network Manager */

let threatGaugeChartInstance = null;
let cachedDevices = [];
let discoveredScanCache = [];
let currentOperatingMode = 'LAB_SIMULATION';
let liveCaptureReady = false;
let lastModeStatus = null;
const measuredLatencies = new Map();
let demoSwitchPendingRestart = false;

const MAC_CAPTURE_HELP = 'https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html';

function captureState(data) {
  if (!data.capture_mode && !data.capture?.runtime_mode) return { message: 'Capture status unavailable.', label: 'Unknown' };
  const configured = data.capture_mode || 'SIMULATED';
  const runtime = data.capture?.runtime_mode || 'SIMULATED';
  if (configured !== 'LIVE') {
    if (runtime === 'LIVE') return { message: 'Demo capture saved. Restart NetGuard in Settings.', label: 'Restart required', action: { text: 'Open Settings', href: '/settings' } };
    return { message: 'Set capture to Live in Settings.', label: 'Off', action: { text: 'Update Settings', href: '/settings' } };
  }
  if (runtime !== 'LIVE') return { message: 'Live capture saved. Restart NetGuard.', label: 'Restart required' };
  if (data.capture?.error) {
    if (data.capture.error.includes('/dev/bpf')) {
      return { message: 'Capture unavailable: macOS permission required.', label: 'Permission denied', action: { text: 'Capture help', href: MAC_CAPTURE_HELP } };
    }
    if (data.capture.error.includes('Permission denied')) return { message: 'Capture unavailable: permission required.', label: 'Permission denied' };
    return { message: 'Live capture unavailable. Check the interface and process permissions.', label: 'Error' };
  }
  if (!data.capture?.ready) return { message: 'Live capture is starting...', label: 'Starting' };
  return { message: 'Live capture ready.', label: 'Ready' };
}

function updateCaptureAction(link, action) {
  if (!link) return;
  link.classList.toggle('hidden', !action);
  if (!action) return;
  link.textContent = action.text;
  link.href = action.href;
  link.target = action.href.startsWith('https://') ? '_blank' : '_self';
  link.rel = link.target === '_blank' ? 'noopener noreferrer' : '';
}

async function refreshModeStatus() {
  const res = await fetch('/api/mode/status');
  if (!res.ok) throw new Error('Could not check capture status');
  const data = await res.json();
  if (data.status !== 'success') throw new Error(data.message || 'Could not check capture status');
  lastModeStatus = data;
  currentOperatingMode = data.operating_mode;
  liveCaptureReady = data.capture_mode === 'LIVE' && data.capture.ready;
  updateModeUI(currentOperatingMode);
  updateCaptureAvailability(data);
  return data;
}

function updateCaptureAvailability(data = lastModeStatus || { capture: {} }) {
  const importBtn = document.getElementById('btn-import-scan') || document.getElementById('modal-import-btn');
  const notice = document.getElementById('scan-capture-notice');
  const noticeMessage = document.getElementById('scan-capture-message');
  const noticeActionLink = document.getElementById('scan-capture-action-link');
  const liveHelp = document.getElementById('live-mode-help');
  const liveHelpMessage = document.getElementById('live-mode-message');
  const liveActionLink = document.getElementById('live-mode-action-link');
  const settingsStatus = document.getElementById('capture-runtime-status');
  const restartButton = document.getElementById('restart-netguard-btn');
  const liveButton = document.getElementById('btn-mode-live');
  const backendSelect = document.getElementById('quarantine_backend');
  const enforcementLabel = document.getElementById('gauge-enforce-mode');
  const headerMode = document.getElementById('header-mode-badge');
  const floatingSensor = document.getElementById('floating-sensor-status');
  const footerSensor = document.getElementById('footer-sensor-status');
  const floatingLed = document.getElementById('floating-lan-led');
  const floatingPulse = document.getElementById('floating-lan-pulse');
  const state = captureState(data);
  const sensorLabel = liveCaptureReady ? 'Live capture ready' : (currentOperatingMode === 'LAB_SIMULATION' ? 'Simulation active' : 'Live capture unavailable');
  if (headerMode) headerMode.textContent = currentOperatingMode === 'LIVE_LAN' ? 'LIVE' : 'LAB';
  if (floatingSensor) floatingSensor.textContent = sensorLabel;
  if (footerSensor) footerSensor.textContent = sensorLabel;
  if (floatingLed) floatingLed.className = `relative inline-flex rounded-full h-2 w-2 ${liveCaptureReady ? 'bg-emerald-500' : currentOperatingMode === 'LAB_SIMULATION' ? 'bg-blue-500' : 'bg-rose-500'}`;
  if (floatingPulse) floatingPulse.className = `absolute inline-flex h-full w-full rounded-full opacity-50 ${liveCaptureReady ? 'animate-ping bg-emerald-400' : currentOperatingMode === 'LAB_SIMULATION' ? 'bg-blue-400' : 'bg-rose-400'}`;
  if (importBtn && discoveredScanCache.length) {
    importBtn.disabled = !liveCaptureReady;
    importBtn.title = liveCaptureReady ? 'Import discovered devices for live monitoring' : state.message;
    importBtn.innerHTML = liveCaptureReady
      ? `<i class="fa-solid fa-cloud-arrow-down text-xs mr-1.5"></i><span>Import All Devices (${discoveredScanCache.length})</span>`
      : '<i class="fa-solid fa-lock text-xs mr-1.5"></i><span>Live capture required</span>';
  }
  if (notice) {
    notice.classList.toggle('hidden', liveCaptureReady);
    if (noticeMessage) noticeMessage.textContent = data.capture?.error?.includes('/dev/bpf')
      ? 'Import requires macOS capture permission.'
      : `Import unavailable — ${state.message}`;
  }
  updateCaptureAction(noticeActionLink, state.action);
  if (liveHelp) liveHelp.classList.toggle('hidden', liveCaptureReady);
  if (liveHelpMessage) liveHelpMessage.textContent = state.message;
  updateCaptureAction(liveActionLink, state.action);
  if (liveButton) {
    liveButton.disabled = !liveCaptureReady;
    liveButton.classList.toggle('opacity-50', !liveCaptureReady);
    liveButton.classList.toggle('cursor-not-allowed', !liveCaptureReady);
    liveButton.title = liveCaptureReady ? 'Switch to live LAN monitoring' : state.message;
  }
  if (settingsStatus) {
    settingsStatus.textContent = `Saved: ${data.capture_mode || 'unknown'} · Running: ${data.capture?.runtime_mode || 'unknown'} · Capture: ${state.label}`;
    settingsStatus.title = data.capture?.error || '';
  }
  if (restartButton) restartButton.classList.toggle('hidden', !data.restart_available);
  if (enforcementLabel) {
    const labels = { SIMULATED: 'Simulated ACL policy', WINDOWS: 'Windows host firewall', LINUX: 'Linux host firewall', PFCTL: 'macOS host firewall' };
    enforcementLabel.textContent = labels[data.quarantine_backend] || 'Unknown';
  }
  if (backendSelect) {
    for (const option of backendSelect.options) {
      if (option.value !== 'SIMULATED') option.disabled = currentOperatingMode !== 'LIVE_LAN';
    }
    backendSelect.title = currentOperatingMode === 'LIVE_LAN' ? 'Choose a containment backend' : 'Switch to Live LAN before choosing a host firewall backend';
  }
}

function escapeHtml(string) {
  if (!string) return '';
  const entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  return String(string).replace(/[&<>"'\/]/g, s => entityMap[s]);
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  let bgClass = 'bg-slate-900/95 text-slate-200 border-slate-700/80';
  let icon = '<i class="fa-solid fa-info-circle text-cyan-400 mr-2.5 text-sm"></i>';

  if (type === 'success') {
    bgClass = 'bg-[#091a14]/95 text-emerald-200 border-emerald-700/60 shadow-lg shadow-emerald-950/50';
    icon = '<i class="fa-solid fa-circle-check text-emerald-400 mr-2.5 text-sm"></i>';
  } else if (type === 'error' || type === 'danger') {
    bgClass = 'bg-[#1f0d12]/95 text-rose-200 border-rose-700/60 shadow-lg shadow-rose-950/50';
    icon = '<i class="fa-solid fa-triangle-exclamation text-rose-400 mr-2.5 text-sm"></i>';
  } else if (type === 'warning') {
    bgClass = 'bg-[#1e1507]/95 text-amber-200 border-amber-700/60 shadow-lg shadow-amber-950/50';
    icon = '<i class="fa-solid fa-circle-exclamation text-amber-400 mr-2.5 text-sm"></i>';
  }

  toast.className = `p-3.5 rounded-xl border text-xs flex items-center shadow-xl pointer-events-auto transform transition-all duration-300 translate-y-3 opacity-0 backdrop-blur-md ${bgClass}`;
  toast.innerHTML = `${icon}<span class="font-medium">${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-3', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-3');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function copyToClipboard(text, label = "Address") {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label} copied: ${text}`, 'success');
  }).catch(() => {
    showToast(`Copied: ${text}`, 'info');
  });
}

/* ==========================================================
 * Real Network Scanner & Modal Handlers
 * ========================================================== */

/* ==========================================================
 * Real Subnet Discovery, Active Scan & Hardware Profiling
 * ========================================================== */

let scanProgressTimer = null;

function openNetworkScanModal() {
  const modal = document.getElementById('network-scan-modal');
  if (modal) {
    modal.classList.remove('hidden');
    refreshModeStatus().catch(() => {
      liveCaptureReady = false;
      updateCaptureAvailability({ capture: {} });
    });
    // Ensure network telemetry is fresh
    fetch('/api/network/info')
      .then(res => res.json())
      .then(data => {
        if (data.info) {
          const subEl = document.getElementById('modal-scan-subnet');
          const gwEl = document.getElementById('modal-scan-gateway');
          const ifEl = document.getElementById('modal-scan-iface');
          if (subEl) subEl.innerText = data.info.subnet || '192.168.1.0/24';
          if (gwEl) gwEl.innerText = data.info.gateway_ip || 'Unknown';
          if (ifEl) ifEl.innerText = data.info.interface || 'en0';
        }
      })
      .catch(() => {});

    // If we already have discovered devices, render them
    if (discoveredScanCache && discoveredScanCache.length > 0) {
      renderDiscoveredScanList();
    }
  }
}

function closeNetworkScanModal() {
  const modal = document.getElementById('network-scan-modal');
  if (modal) modal.classList.add('hidden');
  if (scanProgressTimer) clearInterval(scanProgressTimer);
}

async function startNetworkScan() {
  const authBox = document.getElementById('scan-auth-checkbox');
  if (authBox && !authBox.checked) {
    authBox.checked = true; // assist the user
  }

  const progressBox = document.getElementById('scan-progress-box');
  const progressBar = document.getElementById('scan-progress-bar') || document.getElementById('modal-scan-progress-bar');
  const statusPct = document.getElementById('scan-status-pct') || document.getElementById('modal-scan-percentage');
  const statusText = document.getElementById('scan-status-text') || document.getElementById('modal-scan-status');
  const emptyState = document.getElementById('scan-empty-state');
  const listEl = document.getElementById('discovered-devices-list') || document.getElementById('modal-discovered-list');
  const startBtn = document.getElementById('btn-start-scan');
  const importBtn = document.getElementById('btn-import-scan') || document.getElementById('modal-import-btn');
  const counterEl = document.getElementById('scan-summary-counter') || document.getElementById('modal-discovered-count');

  // 1. Show progress box & hide empty state
  if (progressBox) progressBox.classList.remove('hidden');
  if (emptyState) emptyState.classList.add('hidden');
  if (importBtn) {
    importBtn.disabled = true;
    importBtn.classList.add('hidden');
  }

  // 2. Disable start button & show spinner
  if (startBtn) {
    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-xs mr-1.5"></i><span>Scanning Subnet...</span>';
  }

  // 3. Render High-Tech Animated Radar Loader in Results Area
  if (listEl) {
    listEl.innerHTML = `
      <div class="py-10 px-4 flex flex-col items-center justify-center text-center space-y-4">
        <div class="relative flex items-center justify-center">
          <div class="w-16 h-16 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center"></div>
          <div class="absolute w-10 h-10 rounded-full bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <i class="fa-solid fa-satellite-dish text-base animate-pulse"></i>
          </div>
        </div>
        <div>
          <h4 class="text-sm font-bold text-white tracking-wide">Active Subnet Reconnaissance</h4>
          <p id="loader-sub-msg" class="text-xs text-slate-400 mt-1 max-w-sm leading-relaxed">
            Broadcasting multi-vector UDP wake-up bursts (mDNS, SSDP, NetBIOS)...
          </p>
        </div>
        <div class="flex items-center space-x-2 text-[11px] font-mono text-cyan-400">
          <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
          <span id="loader-stage-indicator">Probing 254 hosts across /24 subnet...</span>
        </div>
      </div>
    `;
  }

  let curProgress = 12;
  if (progressBar) progressBar.style.width = '12%';
  if (statusPct) statusPct.innerText = '12%';
  if (statusText) statusText.innerText = 'Broadcasting UDP wake-up packets to subnet...';

  // Smooth multi-stage progress bar animation
  scanProgressTimer = setInterval(() => {
    if (curProgress < 88) {
      curProgress += Math.floor(Math.random() * 5) + 3;
      if (curProgress > 88) curProgress = 88;
      if (progressBar) progressBar.style.width = curProgress + '%';
      if (statusPct) statusPct.innerText = curProgress + '%';

      const loaderMsg = document.getElementById('loader-sub-msg');
      const loaderStage = document.getElementById('loader-stage-indicator');

      if (curProgress < 30) {
        if (statusText) statusText.innerText = 'Broadcasting mDNS, SSDP & NetBIOS wake-up bursts...';
        if (loaderMsg) loaderMsg.innerText = 'Waking sleeping mobile and IoT devices on local Wi-Fi...';
      } else if (curProgress < 60) {
        if (statusText) statusText.innerText = 'Probing device listeners (Smart TVs, iPhones, Android & IoT)...';
        if (loaderMsg) loaderMsg.innerText = 'Probing listener ports across 254 subnet IP addresses...';
      } else {
        if (statusText) statusText.innerText = 'Harvesting kernel ARP cache & fingerprinting host services...';
        if (loaderMsg) loaderMsg.innerText = 'Resolving hardware MAC vendors and hostnames...';
      }
    }
  }, 450);

  try {
    const res = await fetch('/api/network/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authorization_confirmed: true })
    });

    const data = await res.json();
    clearInterval(scanProgressTimer);

    if (!res.ok || data.status === 'error') {
      throw new Error(data.message || `Subnet scan failed (${res.status})`);
    }

    if (progressBar) progressBar.style.width = '100%';
    if (statusPct) statusPct.innerText = '100%';
    if (statusText) statusText.innerText = `Subnet sweep complete. Discovered ${data.devices_count} physical hosts.`;

    discoveredScanCache = data.devices || [];
    renderDiscoveredScanList();

    if (counterEl) {
      counterEl.innerText = `${discoveredScanCache.length} device${discoveredScanCache.length === 1 ? '' : 's'} discovered on LAN`;
    }

    showToast(`Discovered ${discoveredScanCache.length} active physical devices on your network!`, 'success');

  } catch (err) {
    clearInterval(scanProgressTimer);
    if (statusText) statusText.innerText = 'Scan error: ' + (err.message || err);
    if (progressBar) progressBar.style.width = '100%';
    showToast('Subnet scan error: ' + (err.message || err), 'error');

    if (listEl) {
      listEl.innerHTML = `
        <div class="text-center py-6 text-slate-500 text-xs">
          <i class="fa-solid fa-triangle-exclamation text-rose-400 text-xl mb-1"></i>
          <p class="text-slate-300">Scan encountered an issue: ${escapeHtml(err.message || err)}</p>
          <button onclick="startNetworkScan()" class="mt-2 text-cyan-400 underline font-semibold">Try Again</button>
        </div>
      `;
    }
  } finally {
    if (startBtn) {
      startBtn.disabled = false;
      startBtn.innerHTML = '<i class="fa-solid fa-satellite-dish text-xs mr-1.5"></i><span>Re-scan Subnet</span>';
    }
  }
}

function renderDiscoveredScanList() {
  const listEl = document.getElementById('discovered-devices-list') || document.getElementById('modal-discovered-list');
  const emptyState = document.getElementById('scan-empty-state');
  const importBtn = document.getElementById('btn-import-scan') || document.getElementById('modal-import-btn');
  const counterEl = document.getElementById('scan-summary-counter') || document.getElementById('modal-discovered-count');

  if (!listEl) return;
  if (emptyState) emptyState.classList.add('hidden');

  if (!discoveredScanCache || discoveredScanCache.length === 0) {
    listEl.innerHTML = `
      <div class="text-center py-8 text-slate-500 text-xs">
        <i class="fa-solid fa-circle-exclamation text-amber-400 text-2xl mb-2"></i>
        <p class="text-slate-300 font-semibold">No external devices responded to the sweep.</p>
        <p class="text-[11px] text-slate-500 mt-1">You can probe a specific device directly by entering its IP address above.</p>
      </div>
    `;
    if (importBtn) importBtn.classList.add('hidden');
    return;
  }

  if (counterEl) {
    counterEl.innerText = `${discoveredScanCache.length} device${discoveredScanCache.length === 1 ? '' : 's'} discovered on LAN`;
  }

  // Reveal import button with device count
  if (importBtn) {
    importBtn.classList.remove('hidden');
    updateCaptureAvailability();
  }

  listEl.innerHTML = discoveredScanCache.map(d => {
    let icon = 'fa-laptop text-blue-400';
    if (d.device_type === 'Router') icon = 'fa-network-wired text-cyan-400';
    else if (d.device_type === 'Phone') icon = 'fa-mobile-screen text-indigo-400';
    else if (d.device_type === 'Printer') icon = 'fa-print text-emerald-400';
    else if (d.device_type === 'Smart TV') icon = 'fa-tv text-purple-400';
    else if (d.device_type === 'Camera' || d.device_type === 'CCTV') icon = 'fa-video text-amber-400';
    else if (d.device_type === 'IoT') icon = 'fa-microchip text-teal-400';
    else if (d.device_type === 'Workstation' || d.device_type === 'Laptop') icon = 'fa-laptop text-blue-400';

    const portsBadge = (d.open_ports && d.open_ports.length > 0)
      ? `<span class="px-1.5 py-0.2 rounded text-[9px] font-mono bg-slate-800 text-slate-400 border border-slate-700">Ports: ${d.open_ports.slice(0, 3).join(', ')}${d.open_ports.length > 3 ? '...' : ''}</span>`
      : '';

    return `
      <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs hover:border-cyan-800/60 transition">
        <div class="flex items-center space-x-3 truncate">
          <div class="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center shrink-0">
            <i class="fa-solid ${icon}"></i>
          </div>
          <div class="truncate">
            <div class="flex items-center space-x-2">
              <span class="font-bold text-white">${escapeHtml(d.name)}</span>
              ${d.is_gateway ? '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">GATEWAY</span>' : ''}
              ${d.is_localhost ? '<span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-blue-950 text-blue-400 border border-blue-800">THIS HOST</span>' : ''}
              ${portsBadge}
            </div>
            <div class="text-[11px] font-mono text-slate-400 mt-0.5">
              <span>IP: <strong class="text-cyan-300">${d.ip}</strong></span> • 
              <span>MAC: ${d.mac}</span>
            </div>
          </div>
        </div>
        <div class="flex items-center space-x-2 shrink-0 ml-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
            🟢 ${d.latency_ms}ms
          </span>
          <span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-medium hidden sm:inline-block">
            ${escapeHtml(d.vendor || 'Physical LAN')}
          </span>
        </div>
      </div>
    `;
  }).join('');
}

async function probeSingleTargetIp() {
  const ipInput = document.getElementById('direct-probe-ip') || document.getElementById('modal-direct-ip');
  const probeBtn = document.getElementById('btn-probe-ip') || document.getElementById('modal-probe-btn');
  if (!ipInput) return;

  const targetIp = ipInput.value.trim();
  if (!targetIp) {
    showToast('Please enter an IP address to probe (e.g. 192.168.1.80)', 'warning');
    ipInput.focus();
    return;
  }

  const originalBtnHtml = probeBtn ? probeBtn.innerHTML : '';
  if (probeBtn) {
    probeBtn.disabled = true;
    probeBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-[11px] mr-1"></i><span>Probing...</span>';
  }

  try {
    const res = await fetch('/api/network/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: targetIp, import: false, authorization_confirmed: true })
    });
    const data = await res.json();

    if (data.status === 'success' && data.device) {
      const dev = data.device;
      const existingIdx = discoveredScanCache.findIndex(x => x.ip === dev.ip || x.mac === dev.mac);
      if (existingIdx >= 0) {
        discoveredScanCache[existingIdx] = dev;
      } else {
        discoveredScanCache.unshift(dev);
      }
      renderDiscoveredScanList();
      showToast(`Target probed: ${dev.name} (${dev.latency_ms}ms)`, 'success');
      ipInput.value = '';
    } else {
      showToast(data.message || 'Target did not respond to probe', 'warning');
    }
  } catch (err) {
    showToast('Probe request failed: ' + err, 'error');
  } finally {
    if (probeBtn) {
      probeBtn.disabled = false;
      probeBtn.innerHTML = originalBtnHtml;
    }
  }
}

async function importScannedDevices() {
  if (!discoveredScanCache || discoveredScanCache.length === 0) {
    showToast('No discovered devices to import. Run a subnet scan first.', 'warning');
    return;
  }

  try {
    await refreshModeStatus();
    if (!liveCaptureReady) return;
  } catch (e) {
    showToast(e.message || 'Could not check capture status', 'error');
    return;
  }

  const importBtn = document.getElementById('btn-import-scan') || document.getElementById('modal-import-btn');
  if (importBtn) {
    importBtn.disabled = true;
    importBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-xs mr-1.5"></i><span>Importing Devices...</span>';
  }

  try {
    const res = await fetch('/api/network/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ devices: discoveredScanCache, authorization_confirmed: true })
    });
    const data = await res.json();

    if (!res.ok || data.status === 'error') {
      throw new Error(data.message || 'Failed to import devices');
    }

    currentOperatingMode = 'LIVE_LAN';
    updateModeUI('LIVE_LAN');
    await refreshModeStatus();
    showToast(`Successfully imported ${data.imported_count} devices to live monitoring!`, 'success');
    closeNetworkScanModal();
    refreshDashboard();
    if (typeof fetchDevices === 'function') fetchDevices();

  } catch (e) {
    showToast('Error importing devices: ' + (e.message || e), 'error');
  } finally {
    if (importBtn) {
      updateCaptureAvailability();
    }
  }
}

// Backward compatibility function aliases
window.startRealLanScan = startNetworkScan;
window.importDiscoveredAndClose = importScannedDevices;
window.probeDirectIp = probeSingleTargetIp;

/* ==========================================================
 * Operating Mode Switcher (Live LAN vs Demo Lab)
 * ========================================================== */

async function switchOperationMode(mode, showFeedback = true, confirmed = false) {
  if (mode === 'LIVE_LAN') {
    try {
      await refreshModeStatus();
      if (!liveCaptureReady) return;
    } catch (e) {
      showToast(e.message || 'Could not check capture status', 'error');
      return;
    }
  }
  if (mode === 'LIVE_LAN' && !confirm('Switching to live LAN removes the academic demo inventory and starts active discovery. Continue only on a network you are authorised to assess.')) {
    return;
  }
  if (mode === 'LAB_SIMULATION' && currentOperatingMode === 'LIVE_LAN' && !confirmed) {
    await openDemoSwitchDialog();
    return;
  }
  try {
    const res = await fetch('/api/mode/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode, authorization_confirmed: true })
    });
    const data = await res.json();
    if (!res.ok || data.status !== 'success') {
      throw new Error(data.message || `Mode switch failed (${res.status})`);
    }

    currentOperatingMode = mode;
    updateModeUI(mode);
    await refreshModeStatus();

    if (showFeedback) {
      showToast(data.message || `Switched to ${mode}`, 'success');
    }
    refreshDashboard();
    return data;
  } catch (e) {
    showToast('Failed to switch mode: ' + e, 'error');
    return null;
  }
}

async function openDemoSwitchDialog() {
  try {
    await refreshModeStatus();
  } catch (e) {
    showToast(e.message || 'Could not verify the current mode', 'error');
    return;
  }
  if (currentOperatingMode !== 'LIVE_LAN') return;
  const dialog = document.getElementById('demo-switch-dialog');
  const message = document.getElementById('demo-switch-message');
  const button = document.getElementById('demo-switch-confirm');
  if (!dialog) return;
  if (message && !lastModeStatus?.restart_available) {
    message.textContent = 'This clears the live inventory and alerts and sets capture to Simulated. Restart NetGuard manually after switching to apply the capture setting.';
  }
  if (button && !lastModeStatus?.restart_available) button.textContent = 'Switch to Demo Lab';
  dialog.classList.remove('hidden');
  document.getElementById('demo-switch-cancel')?.focus();
}

function closeDemoSwitchDialog() {
  document.getElementById('demo-switch-dialog')?.classList.add('hidden');
  document.getElementById('btn-mode-demo')?.focus();
}

async function restartNetGuardAndWait() {
  const response = await fetch('/api/system/restart', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authorization_confirmed: true })
  });
  const result = await response.json();
  if (!response.ok || result.status !== 'success') throw new Error(result.message || 'Restart failed');
  for (let attempt = 0; attempt < 40; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 750));
    try {
      const status = await fetch('/api/mode/status', { cache: 'no-store' }).then(res => res.json());
      if (status.status === 'success' && status.boot_id !== result.boot_id) return status;
    } catch (_) {
      // The launcher is replacing the server.
    }
  }
  throw new Error('NetGuard is taking longer to restart. Refresh this page shortly.');
}

async function confirmDemoSwitch() {
  const button = document.getElementById('demo-switch-confirm');
  const message = document.getElementById('demo-switch-message');
  if (!button) return;
  button.disabled = true;
  button.textContent = demoSwitchPendingRestart ? 'Restarting...' : 'Switching...';
  try {
    if (!demoSwitchPendingRestart) {
      const switched = await switchOperationMode('LAB_SIMULATION', false, true);
      if (!switched) throw new Error('Could not switch to the demo lab');
      demoSwitchPendingRestart = switched.restart_required;
    }
    if (demoSwitchPendingRestart && lastModeStatus?.restart_available) {
      button.textContent = 'Restarting...';
      await restartNetGuardAndWait();
      window.location.reload();
      return;
    }
    closeDemoSwitchDialog();
    showToast(demoSwitchPendingRestart ? 'Demo Lab loaded. Restart NetGuard to apply Simulated capture.' : 'Demo Lab loaded.', demoSwitchPendingRestart ? 'warning' : 'success');
  } catch (e) {
    if (message) message.textContent = `${e.message || e}. ${demoSwitchPendingRestart ? 'The Demo Lab setting is saved; retry the restart.' : 'No settings were changed.'}`;
    showToast(e.message || 'Demo switch failed', 'error');
  } finally {
    button.disabled = false;
    button.textContent = demoSwitchPendingRestart ? 'Retry Restart' : 'Switch and Restart';
  }
}

function updateModeUI(mode) {
  const btnLive = document.getElementById('btn-mode-live');
  const btnDemo = document.getElementById('btn-mode-demo');
  const envTitle = document.getElementById('active-env-title');
  const envBadge = document.getElementById('active-mode-badge');
  const envSub = document.getElementById('active-env-subtitle');
  const labOnly = mode !== 'LAB_SIMULATION';
  const labNotice = document.getElementById('lab-mode-notice');
  if (labNotice) labNotice.classList.toggle('hidden', !labOnly);
  document.querySelectorAll('[onclick^="runDemoStep("], [onclick^="triggerSpecificAttack("], [onclick^="quickResetDemo("]').forEach(button => {
    button.disabled = labOnly;
    button.title = labOnly ? 'Switch to Academic Demo Lab to run synthetic scenarios' : '';
    button.classList.toggle('opacity-50', labOnly);
    button.classList.toggle('cursor-not-allowed', labOnly);
  });

  const baseModeClasses = 'mode-select-btn px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1.5';
  if (btnDemo) {
    const selected = mode !== 'LIVE_LAN';
    btnDemo.className = `${baseModeClasses} ${selected ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`;
    btnDemo.setAttribute('aria-pressed', String(selected));
  }
  if (btnLive) {
    const selected = mode === 'LIVE_LAN';
    btnLive.className = `${baseModeClasses} ${selected ? 'bg-emerald-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`;
    btnLive.setAttribute('aria-pressed', String(selected));
  }

  if (mode === 'LIVE_LAN') {
    if (envTitle) envTitle.innerText = 'Live LAN monitoring';
    if (envBadge) {
      envBadge.innerText = 'LIVE INVENTORY';
      envBadge.className = 'px-2 py-0.2 rounded-full text-[10px] font-mono font-bold bg-emerald-950/90 text-emerald-400 border border-emerald-800/60';
    }
    if (envSub) envSub.innerText = 'Inventory was discovered on the local LAN. Capture coverage depends on the monitoring interface and network position.';
  } else {
    if (envTitle) envTitle.innerText = 'Academic demonstration lab';
    if (envBadge) {
      envBadge.innerText = 'SIMULATED DATA';
      envBadge.className = 'px-2 py-0.2 rounded-full text-[10px] font-mono font-bold bg-cyan-950/90 text-cyan-400 border border-cyan-800/60';
    }
    if (envSub) envSub.innerText = 'Synthetic traffic is being evaluated against seeded device baselines. Switch to Live LAN only on an authorised network.';
  }
}

/* ==========================================================
 * Real Device Actions: Live Ping & Port Scan
 * ========================================================== */

async function pingDevice(deviceId, ip) {
  if (!confirm(`Check connectivity to ${ip}? Continue only if you own this device or have authorisation to assess it.`)) return;
  showToast(`Pinging ${ip}...`, 'info');
  try {
    const res = await fetch('/api/network/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, authorization_confirmed: true })
    });
    const data = await res.json();
    if (data.status === 'success') {
      showToast(`Ping to ${ip}: ${data.latency_ms} ms round-trip`, 'success');
      measuredLatencies.set(deviceId, data.latency_ms);
      const latEl = document.getElementById(`dev-lat-${deviceId}`);
      if (latEl) {
        latEl.textContent = `${data.latency_ms} ms`;
        latEl.classList.replace('text-slate-400', 'text-emerald-400');
        latEl.title = 'Measured by ping in this browser session';
      }
    } else {
      showToast(`Ping to ${ip} failed`, 'warning');
    }
  } catch (e) {
    showToast('Ping error: ' + e, 'error');
  }
}

async function portScanDevice(deviceId, ip) {
  if (!confirm(`Check standard TCP ports on ${ip}? Continue only if you own this device or have authorisation to assess it.`)) return;
  showToast(`Scanning open ports on ${ip}...`, 'info');
  try {
    const res = await fetch('/api/network/port-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ip, authorization_confirmed: true })
    });
    const data = await res.json();
    if (data.status === 'success') {
      const open = data.open_ports;
      if (open.length > 0) {
        showToast(`Open ports on ${ip}: ${open.join(', ')}`, 'warning');
      } else {
        showToast(`No standard open ports detected on ${ip} (Stealth Mode)`, 'info');
      }
    }
  } catch (e) {
    showToast('Port scan error: ' + e, 'error');
  }
}

/* ==========================================================
 * Quarantine, Whitelist & Reset
 * ========================================================== */

async function quickResetDemo() {
  if (!confirm("Reset database to clean normal baseline? All simulated attacks and alerts will be cleared.")) {
    return;
  }
  try {
    const res = await fetch('/api/simulation/reset', { method: 'POST' });
    const data = await res.json();
    if (!res.ok || data.status !== 'success') throw new Error(data.message || 'Reset failed');
    showToast(data.message || 'Environment reset to baseline', 'success');
    refreshDashboard();
  } catch (e) {
    showToast('Failed to reset demo: ' + e, 'error');
  }
}

async function quarantineDevicePrompt(deviceId) {
  const reason = prompt("Enter quarantine trigger reason / notes:", "Manual administrator isolation via console");
  if (!reason) return;
  if (!confirm('Quarantine will change this host’s state and generate an enforcement action. Proceed?')) return;

  try {
    const res = await fetch(`/api/devices/${deviceId}/quarantine`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: reason, authorization_confirmed: true })
    });
    const data = await res.json();
    if (data.status === 'success') {
      showToast(data.message, 'danger');
    } else {
      showToast(data.message, 'warning');
    }
    refreshDashboard();
    if (window.location.pathname.startsWith('/device/')) {
      setTimeout(() => window.location.reload(), 300);
    } else if (typeof fetchDevices === 'function') {
      fetchDevices();
    }
  } catch (e) {
    showToast('Error quarantining device: ' + e, 'error');
  }
}

async function releaseDevice(deviceId) {
  if (!confirm('Release this host from quarantine and restore its monitoring status?')) return;
  try {
    const res = await fetch(`/api/devices/${deviceId}/release`, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'success') {
      showToast(data.message, 'success');
    } else {
      showToast(data.message, 'warning');
    }
    refreshDashboard();
    if (window.location.pathname.startsWith('/device/')) {
      setTimeout(() => window.location.reload(), 300);
    } else if (typeof fetchDevices === 'function') {
      fetchDevices();
    }
  } catch (e) {
    showToast('Error releasing device: ' + e, 'error');
  }
}

async function toggleWhitelist(deviceId) {
  try {
    const res = await fetch(`/api/devices/${deviceId}/whitelist`, { method: 'POST' });
    const data = await res.json();
    showToast(data.message, 'info');
    refreshDashboard();
    if (window.location.pathname.startsWith('/device/')) {
      setTimeout(() => window.location.reload(), 300);
    } else if (typeof fetchDevices === 'function') {
      fetchDevices();
    }
  } catch (e) {
    showToast('Error updating whitelist: ' + e, 'error');
  }
}

/* ==========================================================
 * Live Dashboard Refresh Loop
 * ========================================================== */

async function loadNetworkInfo() {
  try {
    const res = await fetch('/api/network/info');
    const data = await res.json();
    if (data.info) {
      const info = data.info;
      const hostIpEl = document.getElementById('nav-host-ip');
      const gwIpEl = document.getElementById('nav-gw-ip');
      const ifaceEl = document.getElementById('env-iface-name');
      const subnetEl = document.getElementById('env-subnet-name');
      const floatIpEl = document.getElementById('floating-collapsed-ip');
      const floatSubnetEl = document.getElementById('floating-subnet');
      const floatGwEl = document.getElementById('floating-gw-ip');
      const floatIfaceEl = document.getElementById('floating-iface');

      if (hostIpEl) hostIpEl.innerText = info.host_ip;
      if (gwIpEl) gwIpEl.innerText = info.gateway_ip;
      if (ifaceEl) ifaceEl.innerText = info.interface;
      if (subnetEl) subnetEl.innerText = info.subnet;
      if (floatIpEl) floatIpEl.innerText = info.host_ip;
      if (floatSubnetEl) floatSubnetEl.innerText = info.subnet;
      if (floatGwEl) floatGwEl.innerText = info.gateway_ip;
      if (floatIfaceEl) floatIfaceEl.innerText = info.interface;
    }
  } catch (e) {
    console.error('Error fetching net info:', e);
  }
}

async function refreshDashboard() {
  try {
    const [devRes, statsRes, alertRes] = await Promise.all([
      fetch('/api/devices'),
      fetch('/api/stats/overview'),
      fetch('/api/alerts?limit=6&unack=1')
    ]);

    const devData = await devRes.json();
    const statsData = await statsRes.json();
    const alertData = await alertRes.json();

    cachedDevices = devData.devices || [];

    // 1. Update KPI Counters safely (null-safe for non-dashboard pages)
    const setElText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val;
    };
    setElText('stat-total-devices', statsData.total_devices || 0);
    setElText('stat-normal-devices', statsData.normal_count || 0);
    setElText('stat-suspicious-devices', statsData.suspicious_count || 0);
    setElText('stat-critical-devices', statsData.critical_count || 0);
    setElText('stat-quarantined-devices', statsData.quarantined_count || 0);
    setElText('stat-active-alerts', statsData.active_alerts || 0);
    setElText('device-count-pill', `${statsData.total_devices || 0} Active`);
    setElText('devices-total-badge', `${statsData.total_devices || 0} Monitored`);

    // Badges in Navbar
    const navAlert = document.getElementById('nav-alert-badge');
    if (navAlert) {
      if (statsData.active_alerts > 0) {
        navAlert.innerText = statsData.active_alerts;
        navAlert.classList.remove('hidden');
      } else {
        navAlert.classList.add('hidden');
      }
    }

    const navQuar = document.getElementById('nav-quarantine-badge');
    if (navQuar) {
      if (statsData.quarantined_count > 0) {
        navQuar.innerText = statsData.quarantined_count;
        navQuar.classList.remove('hidden');
      } else {
        navQuar.classList.add('hidden');
      }
    }

    // 2. Update Peak Threat Gauge
    updateThreatGauge(statsData.max_risk_score || 0);

    // Update Threat sub-metrics
    const highestDev = cachedDevices.reduce((max, d) => (d.current_drift_score > (max ? max.current_drift_score : 0) ? d : max), null);
    const highestHostEl = document.getElementById('gauge-highest-host');
    if (highestHostEl) {
      if (highestDev && highestDev.current_drift_score > 0) {
        highestHostEl.innerText = `${highestDev.name.split(' ')[0]} (${highestDev.current_drift_score.toFixed(1)}%)`;
      } else {
        highestHostEl.innerText = 'None (0.0%)';
      }
    }

    // 3. Render Device Table
    renderDeviceTable(cachedDevices);

    // 4. Render Live Event Feed
    renderLiveAlertFeed(alertData.alerts || []);

  } catch (e) {
    console.error('Error refreshing dashboard:', e);
  }
}

function filterDeviceTable() {
  renderDeviceTable(cachedDevices);
}

async function fetchDevices() {
  try {
    const res = await fetch('/api/devices');
    const data = await res.json();
    cachedDevices = data.devices || [];
    renderDeviceTable(cachedDevices);
    const badge = document.getElementById('devices-total-badge');
    if (badge) badge.innerText = `${cachedDevices.length} Monitored`;
  } catch (e) {
    console.error('Error fetching devices:', e);
  }
}

function renderDeviceTable(devices) {
  const bodies = [document.getElementById('device-table-body'), document.getElementById('devices-table-body')].filter(Boolean);
  if (bodies.length === 0) return;

  const searchInput = document.getElementById('device-search-input');
  const searchQuery = (searchInput ? searchInput.value : '').toLowerCase();

  const catSelect = document.getElementById('category-filter') || document.getElementById('device-category-filter');
  const catFilter = catSelect ? catSelect.value : 'ALL';

  const statusSelect = document.getElementById('status-filter') || document.getElementById('device-status-filter');
  const statusFilter = statusSelect ? statusSelect.value : 'ALL';

  let filtered = devices.filter(d => {
    const matchSearch = (d.name || '').toLowerCase().includes(searchQuery) ||
                        (d.ip || '').toLowerCase().includes(searchQuery) ||
                        (d.mac || '').toLowerCase().includes(searchQuery) ||
                        (d.vendor || '').toLowerCase().includes(searchQuery);
    const matchCat = (catFilter === 'ALL' || catFilter === '') || (d.device_type.toLowerCase() === catFilter.toLowerCase());
    const matchStatus = (statusFilter === 'ALL' || statusFilter === '') || (d.status.toLowerCase() === statusFilter.toLowerCase());
    return matchSearch && matchCat && matchStatus;
  });

  if (devices.length === 0) {
    bodies.forEach(b => {
      b.innerHTML = `
        <tr>
          <td colspan="8" class="py-14 text-center">
            <div class="max-w-md mx-auto space-y-3 px-4">
              <div class="w-12 h-12 mx-auto rounded-2xl bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
                <i class="fa-solid fa-satellite-dish text-xl"></i>
              </div>
              <div class="text-slate-200 text-sm font-bold">Clean Monitoring State — No Devices Stored</div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Click <button onclick="openNetworkScanModal()" class="text-cyan-400 underline font-semibold hover:text-cyan-300">Scan</button> in the top navigation bar to discover and import real physical endpoints on your network, or visit the <a href="/academic" class="text-indigo-400 underline font-semibold hover:text-indigo-300">Academic Suite</a> to run viva evaluation scenarios.
              </p>
            </div>
          </td>
        </tr>
      `;
    });
    return;
  }

  if (filtered.length === 0) {
    bodies.forEach(b => {
      b.innerHTML = `<tr><td colspan="8" class="py-12 text-center text-slate-500 text-xs">No devices match your current search/filter criteria.</td></tr>`;
    });
    return;
  }

  const rowsHtml = filtered.map(d => {
    let statusBadge = 'badge-low';
    if (d.status === 'Suspicious') statusBadge = 'badge-medium';
    else if (d.status === 'Critical') statusBadge = 'badge-high';
    else if (d.status === 'Quarantined') statusBadge = 'badge-quarantined';

    // Vendor / Brand Icon
    let brandIcon = 'fa-laptop text-blue-400';
    let brandName = d.vendor || 'Workstation';
    const nameLower = (d.name || '').toLowerCase();
    const typeLower = (d.device_type || '').toLowerCase();
    const isLearningBaseline = !Number(d.baseline_locked);
    const learningLabel = isLearningBaseline
      ? `<span class="text-amber-400 font-semibold">• Learning baseline ${Math.min(Number(d.baseline_samples) || 0, 20)}/20</span>`
      : '';

    if (typeLower.includes('router') || nameLower.includes('gateway')) {
      brandIcon = 'fa-network-wired text-blue-400';
      brandName = d.vendor || 'Router / Gateway';
    } else if (typeLower.includes('phone') || nameLower.includes('mobile')) {
      brandIcon = 'fa-mobile-screen text-indigo-400';
      brandName = d.vendor || 'Smartphone';
    } else if (typeLower.includes('printer')) {
      brandIcon = 'fa-print text-emerald-400';
      brandName = d.vendor || 'Network Printer';
    } else if (typeLower.includes('cctv') || nameLower.includes('cam')) {
      brandIcon = 'fa-video text-amber-400';
      brandName = d.vendor || 'CCTV Camera';
    } else if (nameLower.includes('apple') || (d.vendor || '').toLowerCase().includes('apple')) {
      brandIcon = 'fa-brands fa-apple text-slate-300';
      brandName = d.vendor || 'Apple Device';
    }

    const measuredLatency = measuredLatencies.get(d.id);
    let riskBarGradient = 'from-emerald-500 to-teal-400';
    if (d.status === 'Critical' || d.current_risk_score >= 70) riskBarGradient = 'from-rose-500 to-red-600';
    else if (d.status === 'Suspicious' || d.current_risk_score >= 40) riskBarGradient = 'from-amber-500 to-orange-500';

    return `
      <tr class="hover:bg-slate-900/40 transition">
        <!-- Hardware & Vendor -->
        <td class="py-3 px-4">
          <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center">
              <i class="fa-solid ${brandIcon} text-sm"></i>
            </div>
            <div>
              <a href="/device/${d.id}" class="font-bold text-white hover:text-blue-400 transition flex items-center space-x-1.5">
                <span>${escapeHtml(d.name)}</span>
              </a>
              <div class="flex items-center space-x-2 text-[10px] text-slate-400 mt-0.5">
                <span>${escapeHtml(brandName)}</span>
                ${d.is_whitelisted ? '<span class="text-blue-400 font-semibold">• <i class="fa-solid fa-shield"></i> Whitelisted</span>' : ''}
                ${learningLabel}
              </div>
            </div>
          </div>
        </td>

        <!-- IP & MAC -->
        <td class="py-3 px-4 font-mono text-[11px]">
          <div class="flex items-center space-x-1.5">
            <span class="text-slate-200 font-semibold">${d.ip}</span>
            <button onclick="copyToClipboard('${d.ip}', 'IP')" title="Copy IP" class="text-slate-500 hover:text-blue-400 transition text-[10px]">
              <i class="fa-solid fa-copy"></i>
            </button>
          </div>
          <div class="flex items-center space-x-1 text-slate-500 text-[10px]">
            <span>${d.mac}</span>
          </div>
        </td>

        <!-- Category -->
        <td class="py-3 px-4 text-slate-300 font-medium text-[11px]">
          ${escapeHtml(d.device_type)}
        </td>

        <!-- Live Latency -->
        <td class="py-3 px-4 font-mono">
          <span id="dev-lat-${d.id}" title="${measuredLatency == null ? 'Use the Ping action to measure latency' : 'Measured by ping in this browser session'}" class="px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-900 border border-slate-800 ${measuredLatency == null ? 'text-slate-400' : 'text-emerald-400'}">
            ${measuredLatency == null ? 'Not measured' : `${measuredLatency} ms`}
          </span>
        </td>

        <!-- Behavior Drift -->
        <td class="py-3 px-4 font-mono">
          <span class="${d.current_drift_score > 50 ? 'text-rose-400 font-bold' : (d.current_drift_score > 20 ? 'text-amber-400 font-semibold' : 'text-slate-400')}">
            ${d.current_drift_score > 0 ? '&uarr; ' : ''}${d.current_drift_score.toFixed(1)}%
          </span>
        </td>

        <!-- Risk Score Bar -->
        <td class="py-3 px-4">
          <div class="flex items-center space-x-2.5">
            <div class="w-16 bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
              <div class="bg-gradient-to-r ${riskBarGradient} h-1.5 rounded-full transition-all duration-300" style="width: ${Math.max(4, d.current_risk_score)}%"></div>
            </div>
            <span class="font-mono font-bold text-xs ${d.current_risk_score >= 70 ? 'text-rose-400' : (d.current_risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400')}">
              ${d.current_risk_score}
            </span>
          </div>
        </td>

        <!-- Status -->
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ${statusBadge}">
            ${d.status}
          </span>
        </td>

        <!-- Device actions -->
        <td class="py-3 px-4 text-right">
          <div class="flex items-center justify-end gap-1.5 whitespace-nowrap">
            <!-- Ping Button -->
            <button onclick="pingDevice(${d.id}, '${d.ip}')" aria-label="Ping ${escapeHtml(d.name)}" class="device-action rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-400 border border-slate-700 transition" title="Ping device">
              <i class="fa-solid fa-bolt text-xs"></i>
            </button>
            
            <!-- Port Scan Button -->
            <button onclick="portScanDevice(${d.id}, '${d.ip}')" aria-label="Check ports on ${escapeHtml(d.name)}" class="device-action rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-blue-400 border border-slate-700 transition" title="Check standard ports">
              <i class="fa-solid fa-satellite-dish text-xs"></i>
            </button>

            <!-- Inspect Button -->
            <a href="/device/${d.id}" aria-label="Inspect ${escapeHtml(d.name)}" class="device-action rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 border border-slate-700 transition" title="Inspect behavioural profile">
              <i class="fa-solid fa-chart-line text-xs"></i>
            </a>

            <!-- Quarantine Toggle -->
            ${d.is_quarantined ? `
              <button onclick="releaseDevice(${d.id})" aria-label="Release ${escapeHtml(d.name)} from quarantine" class="device-action rounded-lg bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 transition" title="Release from quarantine">
                <i class="fa-solid fa-unlock text-xs"></i>
              </button>
            ` : `
              <button onclick="quarantineDevicePrompt(${d.id})" aria-label="Quarantine ${escapeHtml(d.name)}" class="device-action rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700 transition" title="Quarantine host">
                <i class="fa-solid fa-ban text-xs"></i>
              </button>
            `}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  bodies.forEach(b => {
    b.innerHTML = rowsHtml;
  });
}

function renderLiveAlertFeed(alerts) {
  const container = document.getElementById('live-alert-feed');
  if (!container) return;
  const renderKey = JSON.stringify(alerts.map(a => [a.id, a.indicator, a.severity, a.message, a.timestamp, a.device_id]));
  if (container.dataset.renderKey === renderKey) return;
  const priorScrollTop = container.scrollTop;
  const priorScrollHeight = container.scrollHeight;
  container.dataset.renderKey = renderKey;

  if (alerts.length === 0) {
    container.innerHTML = `
      <div class="py-8 px-4 flex flex-col items-center justify-center text-center space-y-2.5">
        <div class="w-12 h-12 rounded-xl bg-emerald-950/70 border border-emerald-500/30 flex items-center justify-center shadow-lg shadow-emerald-950/40 ring-1 ring-emerald-500/20">
          <svg class="w-6 h-6 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div>
          <h4 class="text-xs font-bold text-white tracking-wide">No current anomalies</h4>
          <p class="text-[11px] text-slate-400 mt-1 max-w-sm leading-relaxed">
            Current sample data is within the configured behavioural thresholds. New detections will appear here.
          </p>
        </div>
        <div class="flex items-center space-x-2 pt-1 text-[10px] font-mono text-slate-500">
          <span class="inline-flex items-center text-emerald-400 font-semibold"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 animate-pulse"></span>Standing By</span>
          <span>&bull;</span>
          <span>Threshold T1=40 / T2=70</span>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = alerts.map(a => {
    let iconClass = 'fa-solid fa-triangle-exclamation text-rose-400';
    let pillColor = 'badge-high';
    if (a.severity === 'Low') {
      iconClass = 'fa-solid fa-circle-info text-sky-400';
      pillColor = 'badge-info';
    } else if (a.severity === 'Medium') {
      iconClass = 'fa-solid fa-circle-exclamation text-amber-400';
      pillColor = 'badge-medium';
    }

    return `
      <div class="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs hover:border-slate-700 transition">
        <div class="flex items-center space-x-3 min-w-0">
          <div class="w-7 h-7 rounded-lg bg-slate-900 flex items-center justify-center shrink-0">
            <i class="${iconClass} text-xs"></i>
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 min-w-0">
              <span class="font-bold text-white truncate">${escapeHtml(a.indicator)}</span>
              <span class="shrink-0 px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${pillColor}">${escapeHtml(a.severity)}</span>
              <span class="text-[10px] text-slate-500 font-mono">• ${new Date(a.timestamp).toLocaleTimeString()}</span>
            </div>
            <p class="text-[11px] text-slate-400 truncate mt-0.5">${escapeHtml(a.message)}</p>
          </div>
        </div>
        <div class="shrink-0 ml-3">
          <a href="/device/${a.device_id}" class="inline-flex items-center min-h-9 px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-cyan-950 text-cyan-400 text-[11px] border border-slate-700/60 font-semibold">
            Inspect &rarr;
          </a>
        </div>
      </div>
    `;
  }).join('');
  container.scrollTop = priorScrollTop < 8 ? 0 : priorScrollTop + container.scrollHeight - priorScrollHeight;
}

function initDashboard() {
  loadNetworkInfo();
  refreshDashboard();
  setInterval(refreshDashboard, 3000);

  const search = document.getElementById('device-search-input');
  if (search) search.addEventListener('input', () => renderDeviceTable(cachedDevices));

  const catFilter = document.getElementById('category-filter');
  if (catFilter) catFilter.addEventListener('change', () => renderDeviceTable(cachedDevices));

  const statusFilter = document.getElementById('status-filter');
  if (statusFilter) statusFilter.addEventListener('change', () => renderDeviceTable(cachedDevices));
}

// Interactive toggle for bottom-right floating LAN widget
function toggleFloatingLan(event) {
  if (event) event.stopPropagation();
  const widget = document.getElementById('floating-lan-widget');
  if (widget) {
    widget.classList.toggle('is-open');
  }
}

// Dismiss floating LAN widget on click outside
document.addEventListener('click', (e) => {
  const widget = document.getElementById('floating-lan-widget');
  if (widget && !widget.contains(e.target)) {
    widget.classList.remove('is-open');
  }
});

// Ensure floating LAN telemetry is loaded across all pages
document.addEventListener('DOMContentLoaded', () => {
  loadNetworkInfo();
  refreshModeStatus()
    .catch(() => {
      liveCaptureReady = false;
      updateCaptureAvailability({ capture: {} });
    });
});

// Dismiss modal on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeNetworkScanModal();
  }
});

// Dismiss modal on clicking backdrop outside card
document.addEventListener('click', (e) => {
  const modal = document.getElementById('network-scan-modal');
  if (modal && !modal.classList.contains('hidden') && e.target === modal) {
    closeNetworkScanModal();
  }
});
