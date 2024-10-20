function showFormSections() {
    const dropdown = document.getElementById('dropdown').value;

    // Hide all sections first
    hideAllSections();

    // Show the relevant section based on the dropdown selection
    switch (dropdown) {
        case 'option1':
            document.getElementById('section1').style.display = 'block';
            break;
        case 'option2':
            document.getElementById('section2').style.display = 'block';
            break;
        case 'option3':
            document.getElementById('section3').style.display = 'block';
            break;
        case 'option4':
            document.getElementById('section4').style.display = 'block';
            break;
        case 'option5':
            document.getElementById('section5').style.display = 'block';
            break;
        case 'option6':
            document.getElementById('section6').style.display = 'block';
            break;
        case 'option7':
            document.getElementById('section7').style.display = 'block';
            break;
        case 'option8':
            document.getElementById('section8').style.display = 'block';
            break;
        default:
            // Hide all sections if no valid option is selected
            hideAllSections();
            break;
    }
}

function hideAllSections() {
    // Hide all form sections
    for (let i = 1; i <= 8; i++) {
        const section = document.getElementById('section' + i);
        if (section) {
            section.style.display = 'none';
        }
    }
}
