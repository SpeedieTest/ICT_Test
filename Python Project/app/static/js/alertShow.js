function toggleDetails(element) {
    const details = element.nextElementSibling;
    if (details.classList.contains('hidden')) {
        details.classList.remove('hidden');
        element.innerHTML = '&#9650;'; // Up arrow
    } else {
        details.classList.add('hidden');
        element.innerHTML = '&#9660;'; // Down arrow
    }
}