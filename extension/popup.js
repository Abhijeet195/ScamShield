document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const resultBox = document.getElementById('resultBox');
  const resultVerdict = document.getElementById('resultVerdict');
  const resultGuidance = document.getElementById('resultGuidance');
  const flagsList = document.getElementById('flagsList');

  scanBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) return;

    scanBtn.textContent = 'Scanning Link...';
    scanBtn.disabled = true;

    try {
      const response = await fetch('http://127.0.0.1:5000/api/url-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });

      const data = await response.json();
      resultBox.style.display = 'block';
      flagsList.innerHTML = '';

      if (data.risk_level === 'high') {
        resultBox.className = 'result-box danger';
        resultVerdict.textContent = '⛔ BLOCK RECOMMENDED: High-Risk URL';
      } else if (data.risk_level === 'medium') {
        resultBox.className = 'result-box warning';
        resultVerdict.textContent = '⚠️ CAUTION: Suspicious Link Detected';
      } else {
        resultBox.className = 'result-box safe';
        resultVerdict.textContent = '✓ Standard URL Structure';
      }

      resultGuidance.textContent = data.guidance || '';

      if (data.details && data.details.flags && data.details.flags.length > 0) {
        data.details.flags.forEach(flag => {
          const li = document.createElement('li');
          li.textContent = flag;
          flagsList.appendChild(li);
        });
      }
    } catch (err) {
      resultBox.style.display = 'block';
      resultBox.className = 'result-box warning';
      resultVerdict.textContent = 'Connection Error';
      resultGuidance.textContent = 'Could not reach ScamShield API on http://127.0.0.1:5000. Ensure Flask is running.';
    } finally {
      scanBtn.textContent = 'Inspect Link Before Clicking';
      scanBtn.disabled = false;
    }
  });
});
