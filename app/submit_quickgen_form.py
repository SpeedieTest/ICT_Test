from app.log_gen.log_gen_ssh import auto_generate_ssh_logs, save_ssh_logs
from app.log_gen.log_gen_filesystem import auto_generate_fs_logs, save_fs_logs
from app.log_gen.log_gen_ftp import auto_generate_ftp_logs, save_ftp_logs
from app.log_gen.log_gen_iptables import generate_random_iptables_logs, save_iptables_logs
from app.log_gen.log_gen_snort import auto_generate_snort_logs, save_snort_logs
from app.log_gen.log_gen_netflow import auto_generate_netflow_logs, save_netflow_logs
from app.log_gen.log_gen_kernel import auto_generate_kernel_logs, save_kernel_logs
from app.log_gen.log_gen_syslog import auto_generate_syslog_logs, save_syslog_logs

def handle_quickgen_form(request):
    # List of form fields to convert
    fields = [
        'ssh_ipexternal', 'ssh_ipexternalbrutefore', 'ssh_brutefore', 'ssh_passwordspray',
        'fs_exfiltration', 'ftp_massdownload', 'ftp_massexfiltration', 'iptables_c2',
        'snort_malware', 'netflow_dos', 'netflow_ddos', 'kernel_uns', 'syslog_tmpexecute'
    ]

    # Dictionary to store the converted values
    converted_values = {}

    # Loop through each field and attempt to convert to integer
    for field in fields:
        try:
            # Try to convert the form value to int, default to 0 if not found, then divide by 100
            converted_values[field] = int(request.form.get(field, 0)) / 100
        except (ValueError, TypeError):
            # If conversion fails, set the value to 0
            converted_values[field] = 0

    # Access individual converted values
    ssh_ipexternal = converted_values['ssh_ipexternal']
    ssh_ipexternalbrutefore = converted_values['ssh_ipexternalbrutefore']
    ssh_brutefore = converted_values['ssh_brutefore']
    ssh_passwordspray = converted_values['ssh_passwordspray']
    fs_exfiltration = converted_values['fs_exfiltration']
    ftp_massdownload = converted_values['ftp_massdownload']
    ftp_massexfiltration = converted_values['ftp_massexfiltration']
    iptables_c2 = converted_values['iptables_c2']
    snort_malware = converted_values['snort_malware']
    netflow_dos = converted_values['netflow_dos']
    netflow_ddos = converted_values['netflow_ddos']
    kernel_uns = converted_values['kernel_uns']
    syslog_tmpexecute = converted_values['syslog_tmpexecute']

    # Generate and save logs based on form values
    sshlogs = auto_generate_ssh_logs(ssh_ipexternal, ssh_ipexternalbrutefore, ssh_brutefore, ssh_passwordspray)
    save_ssh_logs(sshlogs)

    fslogs = auto_generate_fs_logs(fs_exfiltration)
    save_fs_logs(fslogs)

    ftplogs = auto_generate_ftp_logs(ftp_massdownload, ftp_massexfiltration)
    save_ftp_logs(ftplogs)

    iptableslogs = generate_random_iptables_logs(iptables_c2, ssh_ipexternal)
    save_iptables_logs(iptableslogs)

    snortlogs = auto_generate_snort_logs(snort_malware)
    save_snort_logs(snortlogs)

    netflowlogs = auto_generate_netflow_logs(netflow_dos, netflow_ddos)
    save_netflow_logs(netflowlogs)

    kernellogs = auto_generate_kernel_logs(kernel_uns)
    save_kernel_logs(kernellogs)

    syslogs = auto_generate_syslog_logs(syslog_tmpexecute)
    save_syslog_logs(syslogs)

    return "Logs generated successfully!"
