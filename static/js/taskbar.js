document.addEventListener('DOMContentLoaded', function () {
    // Toggle Start Button Menu (Burger Menu)
    const startBtn = document.querySelector('.start-btn');
    const navMenu = document.querySelector('nav ul');

    startBtn.addEventListener('click', function () {
        navMenu.classList.toggle('visible'); // Toggles the visibility of the menu
    });

    // Update Taskbar Time
    function updateTime() {
        const currentTime = document.querySelector('.current-time');
        const now = new Date();
        const hours = now.getHours();
        const minutes = now.getMinutes().toString().padStart(2, '0'); // Pad minutes with zero
        const ampm = hours >= 12 ? 'PM' : 'AM';
        const displayHours = hours % 12 || 12; // Convert to 12-hour format
        currentTime.textContent = `${displayHours}:${minutes} ${ampm}`;
    }

    // Initial time update and set interval to update every minute
    updateTime();
    setInterval(updateTime, 60000); // Update time every minute
});
