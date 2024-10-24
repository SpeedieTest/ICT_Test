function showFormSections() {
    const dropdown = document.getElementById('dropdown').value;

    // Hide all sections and reset the aside text
    hideAllSections();
    resetAsideText();

    // Show the relevant section based on the dropdown selection
    switch (dropdown) {
        case 'option1':
            document.getElementById('section1').style.display = 'block';
            setAsideText("Brute Force Detection: Detects 10 failed login attempts within 10 minutes.");
            break;
        case 'option2':
            document.getElementById('section2').style.display = 'block';
            setAsideText("Media Exfiltration Detection: Detects copying sensitive files to media devices.");
            break;
        case 'option3':
            document.getElementById('section3').style.display = 'block';
            setAsideText("Mass Exfiltration Detection: Detects more than 500GB data exfiltration within 24 hours.");
            break;
        case 'option4':
            document.getElementById('section4').style.display = 'block';
            setAsideText("C2 Server Connection Detection: Detects repeated connections from the same source IP to a known command-and-control server.");
            break;
        case 'option5':
            document.getElementById('section5').style.display = 'block';
            setAsideText("Malware Detection: Detects malware files transferred across the network.");
            break;
        case 'option6':
            document.getElementById('section6').style.display = 'block';
            setAsideText("SYN Flood DoS/DDoS Detection: Detects large volumes of SYN packets from the same or multiple sources within a short period.");
            break;
        case 'option7':
            document.getElementById('section7').style.display = 'block';
            setAsideText("Unknown Process Detection: Detects unusual network services started by unknown processes.");
            break;
        case 'option8':
            document.getElementById('section8').style.display = 'block';
            setAsideText("Temporary File Execution Detection: Detects execution of files from temporary directories like /tmp.");
            break;
        default:
            hideAllSections();
            resetAsideText();
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

function resetAsideText() {
    document.getElementById('aside-hint').innerText = "Select an option to see more information.";
}

function setAsideText(text) {
    document.getElementById('aside-hint').innerText = text;
}
