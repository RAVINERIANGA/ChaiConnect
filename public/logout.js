function logout() {
    fetch('/logout', { method: 'POST' })
        .then(res => {
            if (res.ok) {
                showToast(() => {
                    window.location.href = '/login.html';
                });
            }
            else alert('Logout failed');
        })
        .catch(() => alert('Logout error'));
}
function showToast(callback) {
    const toast = document.getElementById('logoutToast');
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
        if (callback) callback();
    }, 2000);
}