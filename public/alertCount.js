async function loadAlertCount() {
  try {
    const res = await fetch('/alerts/count');
    
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    
    const data = await res.json();

    if (data.success && data.count > 0) {
      const badge = document.getElementById('alertCount');
      if (badge) {
        badge.textContent = data.count;
        badge.style.display = 'inline-block';
      }
    }
  } catch (err) {
    console.error('Failed to load alert count:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadAlertCount();
});