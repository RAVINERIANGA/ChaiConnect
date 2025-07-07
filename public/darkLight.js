document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/me')
    .then(res => res.json())
    .then(user => {
      const userId = user.id || user.email || 'default'; // adjust depending on your API
      const themeKey = `theme-${userId}`;
      const toggleSwitch = document.getElementById('themeToggle');

      const savedTheme = localStorage.getItem(themeKey);
      if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
        toggleSwitch.checked = true;
      }

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
      console.error('Failed to load user info for theme', err);
    });
});
