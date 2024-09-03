from cli import configure
import cli
import re
import json
import time
import subprocess
import os

def show_current_directory_contents():
    # Get the current directory path
    current_directory = os.getcwd()

    # List the contents of the directory
    directory_contents = os.listdir(current_directory)

    # Print the current directory path
    print(f"Current Directory: {current_directory}")

    # Print the contents of the directory
    print("Directory Contents:")
    for item in directory_contents:
        print(item)


if __name__ == "__main__":
    show_current_directory_contents()


def check_file_exists(file, file_system='flash:/'):
    dir_check = 'dir ' + file_system + file
    print('*** Checking to see if %s exists on %s ***' % (file, file_system))
    results = cli.cli(dir_check)
    if 'No such file or directory' in results:
        print('*** The %s does NOT exist on %s ***' % (file, file_system))
        return False
    elif 'Directory of %s%s' % (file_system, file) in results:
        print('*** The %s DOES exist on %s ***' % (file, file_system))
        return True
    else:
        raise ValueError("Unexpected output from check_file_exists")


def file_transfer(tftp_server, file, file_system="flash:/guest-share/"):
    destination = file_system + file
    # Set commands to prepare for file transfer
    commands = ['file prompt quiet',
                'ip tftp blocksize 8192'
                ]
    results = configure(commands)
    print('*** Successfully set "file prompt quiet" on switch ***')
    transfer_file = "copy tftp://%s/%s %s" % (tftp_server, file, destination)
    print('Transferring %s to %s' % (file, file_system))
    transfer_results = cli.cli(transfer_file)
    if 'OK' in transfer_results:
        print('*** %s was transferred successfully!!! ***' % (file))
    elif 'XXX Error opening XXX' in transfer_results:
        raise ValueError("XXX Failed Xfer XXX")


def upgrade_required():
    # Obtains show version output
    sh_version = cli.cli('show version')
    # Check if switch is on approved code: 16.10.01
    pattern = re.escape(software_version)  # Escapes any special characters in the string
    match = re.search(pattern,sh_version)  # Searches for the pattern in 'sh_version'    # Returns False if on approved version or True if upgrade is required
    # Returns False if on approved version or True if upgrade is required
    if match:
        return False
    else:
        return True


def verify_dst_image_md5(image, src_md5, file_system='flash:/'):
    verify_md5 = 'verify /md5 ' + file_system + image
    print('Verifying MD5 for ' + file_system + image)
    dst_md5 = cli.cli(verify_md5)
    if src_md5 in dst_md5:
        print('*** MD5 hashes match!! ***\n')
        return True
    else:
        print('XXX MD5 hashes DO NOT match. XXX')
        return False


def deploy_eem_cleanup_script():
    install_command = 'install remove inactive'
    eem_commands = ['event manager applet cleanup',
                    'event none maxrun 600',
                    'action 1.0 cli command "enable"',
                    'action 2.0 cli command "%s" pattern "y\/n"' % install_command,
                    'action 2.1 cli command "y" pattern "proceed"',
                    'action 2.2 cli command "y"'
                    ]
    results = configure(eem_commands)
    print('*** Successfully configured cleanup EEM script on device! ***')


def deploy_eem_upgrade_script(image):
    install_command = 'install add file flash:' + image + ' activate commit'
    eem_commands = ['event manager applet upgrade',
                    'event none maxrun 600',
                    'action 1.0 cli command "enable"',
                    'action 1.1 cli command "copy running-config startup-config"',
                    'action 2.0 cli command "%s" pattern "y\/n"' % install_command,
                    'action 2.1 cli command "n" pattern "proceed"',
                    'action 2.2 cli command "y"'
                    ]
    results = configure(eem_commands)
    print('*** Successfully configured upgrade EEM script on device! ***')


def get_interfaces_range():
    print("\n\n *** Executing show ip interface brief  *** \n\n")
    cli_command = "sh ip int brief | exclude unassigned"
    interfaces_output = cli.cli(cli_command)
    print(interfaces_output)
    # Regular expression to match the main interfaces (GigabitEthernet1/0/x)
    interface_regex = r"GigabitEthernet1/0/(\d+)"

    # Find all matches in the output
    matches = re.findall(interface_regex, interfaces_output)

    # Convert matches to integers to sort and find the range
    port_numbers = [int(match) for match in matches]
    port_numbers.sort()

    # Determine the range based on the number of ports
    if port_numbers:
        first_port = port_numbers[0]
        last_port = port_numbers[-1]
        return f"GigabitEthernet1/0/{first_port} - {last_port}"
    else:
        return "No GigabitEthernet1/0/x interfaces found"


print("\n\n *** Sample ZTP Day0 Python Script *** \n\n")

# Set Global variables to be used in later functions
"""
# DEVICE SPECIFIC Configurations
"""
tftp_server = "{{TFTP_SERVER}}"
file_transfer(tftp_server=tftp_server, file="config_values.py")

from config_values import device_specific_values
from config_values import device_common_values

show_current_directory_contents()

## set hostname
show_version = cli.cli('show version')
serial = re.search(r"Processor board ID\s+(\S+)", show_version).group(1)

if serial in device_specific_values:
    # hostname = device_specific_values[serial].get('hostname')
    # mgmt_v4_ip = device_specific_values[serial].get('mgmt_v4_ip')
    # mgmt_v4_mask = device_specific_values[serial]['mgmt_v4_mask']
    # mgmt_v6_ip = device_specific_values[serial].get('mgmt_v6_ip')
    mgmt_vlan_number = device_common_values.get('mgmt_vlan', 1)
    # default_gateway = device_specific_values[serial].get('default_gateway')
else:
    # hostname = 'ZTPDefault'  # create a default hostname incase a mapping isn't found
    # mgmt_v4_ip = ""
    # mgmt_v4_mask = ""
    # mgmt_v6_ip = ""
    mgmt_vlan_number = 1
    # default_gateway = ""

# Configure the hostname
# if hostname:
#     cli.configurep(['hostname {}'.format(hostname)])
#     print("the hostname of this device is:", hostname)
#     print("\n")
# Hostname Configuration
{{hostname_enabled}}

# if mgmt_vlan_number:
#     cli.configurep(["interface TenGigabitEthernet1/1/1",
#                     f"description {hostname} management interface",
#                     "switchport mode trunk",
#                     f"no switchport trunk allowed vlan {mgmt_vlan_number}",
#                     "ip arp inspection trust",
#                     "storm-control broadcast level 25.00",
#                     "ip dhcp snooping trust", "end"])

# if mgmt_v4_ip and mgmt_v4_mask:
#     # VLAN and Interface Configuration
#     cli.configurep(["interface Vlan1", "no ip address", "shutdown", "end"])
#     cli.configurep([f"interface Vlan{mgmt_vlan_number}", "description Mgmt", f"ip address {mgmt_v4_ip} {mgmt_v4_mask}", "no ip redirects", "no ip proxy-arp", "no shutdown", "end"])
# else:
#     cli.configurep(["interface Vlan1", "no ip address", "shutdown", "end"])

# IPv4 Management Address Configuration
{{mgmt_v4_ip_enabled}}

# if mgmt_v6_ip:
#     cli.configurep([f"interface Vlan{mgmt_vlan_number}", "description Mgmt", f"ipv6 address {mgmt_v6_ip}/64", "no ip redirects", "no ip proxy-arp", "end"])

# IPv6 Management Address Configuration
{{mgmt_v6_ip_enabled}}

# if default_gateway:
#     # Default Gateway Configuration
#     cli.configurep([f"ip default-gateway {default_gateway}", "end"])

# Default Gateway Configuration
{{default_gateway_enabled}}

"""
DEVICE COMMON CONFIGURATION
"""
# Enable Domain Name
# It's a prerequisite for features like SSH.
{{domain_name_enabled}}

# Enable NTP Servers
# Generally does not depend on other configurations.
{{ntp_servers_enabled}}

# DNS Servers Enabled
# Also usually independent.
{{dns_servers_enabled}}

# Syslog Servers Enabled
# Can be set up independently for logging.
{{syslog_servers_enabled}}

# Enable HTTP and HTTPS Services
# These are basic services that don't typically depend on network-specific configurations.
{{http_value_enabled}}
{{https_value_enabled}}

# Management VLAN Enabled
# Important for network management but requires minimal prerequisites.
{{mgmt_vlan_enabled}}

# DHCP Snooping VLANs Enabled
# Depends on VLAN configurations.
{{dhcp_snooping_vlans_enabled}}

# VLAN Access Enabled
# Basic layer 2 configurations, prerequisite for interfaces to function correctly in their roles.
{{vlan_access_enabled}}

# VLAN Trunk Ports Enabled
# Requires access VLANs to be configured.
{{vlan_trunk_ports_enabled}}

# VTP Enabled
# Requires domain name and VLAN configurations.
{{vtp_enabled}}

# Enabled Secret Enabled
# Basic security setting, but can be set up after initial network configurations.
{{enable_secret_enabled}}

# Username Enabled
# Depends on enabling secret and AAA configurations for authentication.
{{username_enabled}}

# VTY Enabled
# For remote management, requires usernames and passwords to be configured.
{{vty_enabled}}

# AAA Enabled
# Advanced security configuration, typically depends on networking basics being configured.
{{aaa_enabled}}

# NetFlow Collectors Enabled
# Depends on networking setup for accurate flow collection.
{{netflow_collectors_enabled}}

# SNMP Enabled
# For monitoring, depends on network interfaces and IP configurations.
{{snmp_enabled}}

# Telnet Enabled
# Required for meraki catalyst monitoring
{{telnet_enabled}}

# SSHv2 Enabled
# Requires domain name and might depend on AAA for authentication.
{{ssh_value_enabled}}

# Remove ztp files and save config
cli.cli("delete /force flash:/guest-share/*.py")
cli.cli("copy run start")

# IOS XE Upgrade 
upgrade = device_common_values.get('iosxe_enabled', False)
if upgrade:
    img = device_common_values['iosxe_image_name']
    img_md5 =  device_common_values['iosxe_image_md5']
    software_version = f'Cisco IOS XE Software, Version {device_common_values.get("iosxe_version", "")}'

    if upgrade_required():
        print('*** Upgrade is required. Starting upgrade process.. ***\n')
        if check_file_exists(img):
            if not verify_dst_image_md5(img, img_md5):
                print('*** Attempting to transfer image to switch.. ***')
                file_transfer(tftp_server, img, file_system="flash:/")
                if not verify_dst_image_md5(img, img_md5):
                    raise ValueError('Failed Xfer')
        else:
            file_transfer(tftp_server, img, file_system="flash:/")
            if not verify_dst_image_md5(img, img_md5):
                raise ValueError('XXX Failed Xfer XXX')

        print('*** Deploying EEM upgrade script ***')
        deploy_eem_upgrade_script(img)
        print('*** Performing the upgrade - switch will reboot ***\n')
        cli.cli('event manager run upgrade')
        time.sleep(600)
    else:
        print('*** No upgrade is required!!! ***')

    # Cleanup any leftover install files
    print('*** Deploying Cleanup EEM Script ***')
    deploy_eem_cleanup_script()
    print('*** Running Cleanup EEM Script ***')
    cli.cli('event manager run cleanup')
    time.sleep(30)