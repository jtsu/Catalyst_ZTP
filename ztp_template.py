'''
Copyright (c) 2024 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
'''


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


print("\n\n *** ZTP Day0 Python Script *** \n\n")

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
    mgmt_vlan_number = device_common_values.get('mgmt_vlan', 1)
else:
    mgmt_vlan_number = 1


# Hostname Configuration
{{hostname_enabled}}


# IPv4 Management Address Configuration
{{mgmt_v4_ip_enabled}}


# IPv6 Management Address Configuration
{{mgmt_v6_ip_enabled}}


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
