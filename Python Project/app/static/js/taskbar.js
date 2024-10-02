function updateTime() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const timeString = `${hours}:${minutes}`;
    document.getElementById('time').innerText = timeString;
}

setInterval(updateTime, 1000); // Update time every second
window.onload = updateTime; // Set time on page load