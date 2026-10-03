/* NetGuard - Live Demo & Attack Lab Controller */

function logConsole(message, type = 'info') {
  const consoleEl = document.getElementById('sim-console');
  if (!consoleEl) return;

  const line = document.createElement('div');
  const timestamp = new Date().toLocaleTimeString();

  let colorClass = 'text-cyan-400';
  if (type === 'danger' || type === 'critical') colorClass = 'text-rose-400 font-bold';
  else if (type === 'warning' || type === 'suspicious') colorClass = 'text-amber-400';
  else if (type === 'success') colorClass = 'text-emerald-400';

  line.className = `leading-relaxed ${colorClass}`;
  line.innerHTML = `<span class="text-slate-500">[${timestamp}]</span> ${escapeHtml(message)}`;
  consoleEl.appendChild(line);

  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function clearConsole() {
  const consoleEl = document.getElementById('sim-console');
  if (consoleEl) {
    consoleEl.innerHTML = '<div class="text-slate-500">> Console cleared.</div>';
  }
}

async function runDemoStep(stepNumber) {
  logConsole(`Executing Phase ${stepNumber} sequence...`, 'info');

  try {
    const res = await fetch(`/api/simulation/step/${stepNumber}`, { method: 'POST' });
    const data = await res.json();

    if (data.status === 'success' || data.step) {
      const stepInfo = data.result;
      logConsole(`Phase ${stepNumber} Complete: ${stepInfo.title}`, 'success');
      logConsole(`>> ${stepInfo.description}`, 'info');

      if (stepInfo.new_risk_score !== undefined) {
        let riskColor = stepInfo.new_risk_score >= 70 ? 'critical' : (stepInfo.new_risk_score >= 40 ? 'warning' : 'success');
        logConsole(`>> New Risk Score: ${stepInfo.new_risk_score}/100 [Status: ${stepInfo.status}]`, riskColor);
      }
      if (stepInfo.is_quarantined) {
        logConsole(`>> [ALERT] Simulated quarantine recorded. No physical network rule was applied.`, 'critical');
      }

      showToast(`Phase ${stepNumber} Executed: ${stepInfo.title}`, 'success');
    } else {
      logConsole(`Phase execution failed: ${data.message}`, 'danger');
      showToast('Error: ' + data.message, 'error');
    }
  } catch (e) {
    logConsole(`Network / API Error: ${e}`, 'danger');
    showToast('Failed to execute demo step', 'error');
  }
}

async function triggerSpecificAttack(attackType) {
  logConsole(`Injecting attack payload: ${attackType.toUpperCase()}...`, 'warning');

  try {
    const res = await fetch('/api/simulation/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: attackType })
    });
    const data = await res.json();

    if (data.status === 'success') {
      logConsole(`Scenario "${data.result.scenario}" injected on target ${data.result.target || ''}`, 'warning');
      if (data.result.expected_points) {
        logConsole(`>> Indicator Weight: ${data.result.expected_points}`, 'info');
      }
      if (data.result.expected_action) {
        logConsole(`>> Outcome: ${data.result.expected_action}`, 'critical');
      }
      showToast(`Injected: ${data.result.scenario}`, 'warning');
    } else {
      logConsole(`Injection error: ${data.message}`, 'danger');
      showToast('Injection failed: ' + data.message, 'error');
    }
  } catch (e) {
    logConsole(`API Error: ${e}`, 'danger');
    showToast('Request failed', 'error');
  }
}
