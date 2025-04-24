// Admin interface JavaScript functions

// Log filtering function
function filterLogs() {
    const level = document.getElementById('logLevel').value;
    const search = document.getElementById('searchLog').value.toLowerCase();
    const entries = document.getElementsByClassName('log-entry');

    for (let entry of entries) {
        const entryLevel = entry.getElementsByClassName('log-level')[0].textContent;
        const entryText = entry.textContent.toLowerCase();
        
        const levelMatch = level === 'all' || entryLevel === level;
        const searchMatch = search === '' || entryText.includes(search);
        
        entry.style.display = levelMatch && searchMatch ? 'block' : 'none';
    }
}

// Auto-refresh logs every 30 seconds
function setupAutoRefresh() {
    if (document.getElementById('autoRefresh').checked) {
        setTimeout(() => {
            window.location.reload();
        }, 30000);
    }
}

// Initialize log viewer
document.addEventListener('DOMContentLoaded', function() {
    const autoRefresh = document.getElementById('autoRefresh');
    if (autoRefresh) {
        autoRefresh.addEventListener('change', setupAutoRefresh);
    }
});
