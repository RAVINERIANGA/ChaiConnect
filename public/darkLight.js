document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/me')
    .then(res => res.json())
    .then(data => {
      const userId = data.userId;
      const toggleSwitch = document.getElementById('themeToggle');

      if (!toggleSwitch || !userId) return;

      const themeKey = `theme_${userId}`;
      const currentTheme = localStorage.getItem(themeKey);

      // Apply saved theme
      if (currentTheme === 'dark') {
        document.body.classList.add('dark-mode');
        toggleSwitch.checked = true;
      }

      // Listen for toggle changes
      toggleSwitch.addEventListener('change', () => {
        if (toggleSwitch.checked) {
          document.body.classList.add('dark-mode');
          localStorage.setItem(themeKey, 'dark');
        } else {
          document.body.classList.remove('dark-mode');
          localStorage.setItem(themeKey, 'light');
        }
      });
    })
    .catch(err => {
      console.error('Failed to load user info for theme:', err);
    });
});
