const defaultState = { autoAnalyze: false, lastAnalysis: 'Sin análisis aún' };

function updatePopup() {
  chrome.storage.sync.get(defaultState, (items) => {
    const statusValue = document.getElementById('statusValue');
    const lastAnalysis = document.getElementById('lastAnalysis');
    const autoAnalyzeToggle = document.getElementById('autoAnalyzeToggle');

    autoAnalyzeToggle.checked = !!items.autoAnalyze;
    lastAnalysis.textContent = items.lastAnalysis || 'Sin análisis aún';

    if (items.autoAnalyze) {
      statusValue.textContent = 'Protección activa';
      statusValue.style.color = '#1f7a45';
    } else {
      statusValue.textContent = 'Protección manual';
      statusValue.style.color = '#8a5c00';
    }
  });
}

document.getElementById('autoAnalyzeToggle').addEventListener('change', (event) => {
  chrome.storage.sync.set({ autoAnalyze: event.target.checked }, () => {
    updatePopup();
  });
});

document.getElementById('openHelp').addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://github.com/Juaanii7/mailshield#readme' });
});

updatePopup();
