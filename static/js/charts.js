/* NetGuard - Modern Chart.js Visualizers (Peak Threat Arc & Radar Profile) */

let threatGaugeChart = null;
let deviceRadarChart = null;

function updateThreatGauge(score) {
  const ctx = document.getElementById('threatGaugeChart');
  if (!ctx) return;

  const scoreVal = Math.min(100, Math.max(0, parseInt(score) || 0));
  const remaining = 100 - scoreVal;

  let gaugeColor = '#10b981'; // Emerald Safe
  let bandLabel = 'LOW - SECURE';
  let bandClass = 'badge-low';

  if (scoreVal >= 70) {
    gaugeColor = '#f43f5e'; // Rose Critical
    bandLabel = 'CRITICAL BREACH';
    bandClass = 'badge-high';
  } else if (scoreVal >= 40) {
    gaugeColor = '#f59e0b'; // Amber Suspicious
    bandLabel = 'SUSPICIOUS ACTIVITY';
    bandClass = 'badge-medium';
  }

  // Update text values
  const scoreDisplay = document.getElementById('gauge-score-value');
  const labelDisplay = document.getElementById('gauge-band-label');

  if (scoreDisplay) scoreDisplay.innerText = scoreVal;
  if (labelDisplay) {
    labelDisplay.innerText = bandLabel;
    labelDisplay.className = `px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${bandClass}`;
  }

  if (threatGaugeChart) {
    threatGaugeChart.data.datasets[0].data = [scoreVal, remaining];
    threatGaugeChart.data.datasets[0].backgroundColor = [gaugeColor, 'rgba(255, 255, 255, 0.04)'];
    threatGaugeChart.update('none');
  } else {
    threatGaugeChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [scoreVal, remaining],
          backgroundColor: [gaugeColor, 'rgba(255, 255, 255, 0.04)'],
          borderWidth: 0,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '82%',
        circumference: 250,
        rotation: 235,
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false }
        },
        animation: {
          duration: 600,
          easing: 'easeOutQuart'
        }
      }
    });
  }
}

function initDeviceDetailPage(deviceId, baselineData) {
  async function refreshDeviceDetails() {
    try {
      const res = await fetch(`/api/devices/${deviceId}`);
      const data = await res.json();
      if (!data.device) return;

      const dev = data.device;
      const recentSample = (data.samples && data.samples.length > 0) ? data.samples[data.samples.length - 1] : null;

      // Extract observed values
      const observedDns = recentSample ? recentSample.dns_count : baselineData.dns;
      const observedIps = recentSample ? recentSample.distinct_ips_count : baselineData.ips;
      const observedPorts = recentSample ? recentSample.port_count : baselineData.ports;
      const observedBytes = recentSample ? Math.round((recentSample.bytes_sent + recentSample.bytes_recv) / 1024) : baselineData.bytes;

      // Update Breakdown Table
      updateMetricRow('detail-dns', baselineData.dns, observedDns);
      updateMetricRow('detail-ips', baselineData.ips, observedIps);
      updateMetricRow('detail-ports', baselineData.ports, observedPorts);
      updateMetricRow('detail-bytes', baselineData.bytes, observedBytes);

      // Render or Update Radar Chart
      renderRadarChart(baselineData, {
        dns: observedDns,
        ips: observedIps,
        ports: observedPorts,
        bytes: observedBytes
      });

      // Update Risk History Table
      renderRiskHistory(data.risk_history || []);

    } catch (e) {
      console.error('Error loading device details:', e);
    }
  }

  function updateMetricRow(prefix, baseline, observed) {
    const obsEl = document.getElementById(`${prefix}-observed`);
    const driftEl = document.getElementById(`${prefix}-drift`);
    if (!obsEl || !driftEl) return;

    obsEl.innerText = observed;
    const baseSafe = Math.max(1, baseline);
    if (observed > baseSafe) {
      const driftPct = Math.round(((observed - baseSafe) / baseSafe) * 100);
      driftEl.innerHTML = `<span class="text-rose-400 font-bold font-mono">&uarr; ${driftPct}%</span>`;
    } else {
      driftEl.innerHTML = `<span class="text-emerald-400 font-semibold font-mono">&minus; 0%</span>`;
    }
  }

  function renderRadarChart(base, obs) {
    const ctx = document.getElementById('deviceRadarChart');
    if (!ctx) return;

    // Normalize for visual comparison on radar
    const normalize = (val, max) => Math.min(100, Math.round((val / max) * 100));

    const baseNorm = [
      normalize(base.dns, 80),
      normalize(base.ips, 25),
      normalize(base.ports, 15),
      normalize(base.bytes, 1200)
    ];

    const obsNorm = [
      normalize(obs.dns, 80),
      normalize(obs.ips, 25),
      normalize(obs.ports, 15),
      normalize(obs.bytes, 1200)
    ];

    if (deviceRadarChart) {
      deviceRadarChart.data.datasets[0].data = baseNorm;
      deviceRadarChart.data.datasets[1].data = obsNorm;
      deviceRadarChart.update('none');
    } else {
      deviceRadarChart = new Chart(ctx, {
        type: 'radar',
        data: {
          labels: ['DNS Queries', 'Remote IPs', 'Contacted Ports', 'Traffic (KB)'],
          datasets: [
            {
              label: 'Historical Baseline',
              data: baseNorm,
              borderColor: '#3B82F6',
              backgroundColor: 'rgba(59, 130, 246, 0.15)',
              borderWidth: 2,
              pointBackgroundColor: '#3B82F6',
              pointBorderColor: '#fff',
              pointHoverRadius: 5
            },
            {
              label: 'Observed Current',
              data: obsNorm,
              borderColor: '#EF4444',
              backgroundColor: 'rgba(239, 68, 68, 0.2)',
              borderWidth: 2,
              pointBackgroundColor: '#EF4444',
              pointBorderColor: '#fff',
              pointHoverRadius: 5
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              angleLines: { color: '#1E293B' },
              grid: { color: '#1E293B' },
              pointLabels: {
                color: '#94A3B8',
                font: { size: 10, weight: 'bold' }
              },
              ticks: { display: false, max: 100, min: 0 }
            }
          },
          plugins: {
            legend: {
              labels: {
                color: '#CBD5E1',
                boxWidth: 12,
                font: { size: 11 }
              }
            }
          }
        }
      });
    }
  }

  function renderRiskHistory(history) {
    const tbody = document.getElementById('risk-history-tbody');
    if (!tbody) return;

    if (history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="py-6 text-center text-slate-500">No previous risk evaluations logged.</td></tr>`;
      return;
    }

    tbody.innerHTML = history.slice(-10).reverse().map(h => {
      let badgeClass = 'text-emerald-400 font-semibold';
      if (h.total_risk_score >= 70) badgeClass = 'text-rose-400 font-bold';
      else if (h.total_risk_score >= 40) badgeClass = 'text-amber-400 font-bold';

      return `
        <tr class="hover:bg-slate-800/30 transition">
          <td class="py-2.5 px-3 text-slate-400 font-mono">${new Date(h.timestamp).toLocaleTimeString()}</td>
          <td class="py-2.5 px-3 text-slate-300 font-mono">${h.drift_score.toFixed(1)}%</td>
          <td class="py-2.5 px-3 ${h.port_scan_score > 0 ? 'text-rose-400 font-bold' : 'text-slate-600'}">+${h.port_scan_score}</td>
          <td class="py-2.5 px-3 ${h.unknown_device_score > 0 ? 'text-amber-400 font-bold' : 'text-slate-600'}">+${h.unknown_device_score}</td>
          <td class="py-2.5 px-3 ${h.dns_anomaly_score > 0 ? 'text-cyan-400 font-bold' : 'text-slate-600'}">+${h.dns_anomaly_score}</td>
          <td class="py-2.5 px-3 ${h.traffic_spike_score > 0 ? 'text-amber-400 font-bold' : 'text-slate-600'}">+${h.traffic_spike_score}</td>
          <td class="py-2.5 px-3 ${h.unfamiliar_dest_score > 0 ? 'text-amber-400 font-bold' : 'text-slate-600'}">+${h.unfamiliar_dest_score}</td>
          <td class="py-2.5 px-3 font-mono ${badgeClass}">${h.total_risk_score}/100</td>
          <td class="py-2.5 px-3 uppercase text-[10px] font-bold ${badgeClass}">${h.risk_band}</td>
        </tr>
      `;
    }).join('');
  }

  refreshDeviceDetails();
  setInterval(refreshDeviceDetails, 3000);
}
