"""
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
"""

from jinja2 import Environment, BaseLoader

def generate_configuration(enable_device_specific_features, enable_features, TFTP_SERVER=None, SOFTWARE_UPGRADE=None,SOFTWARE_IMAGE_FILE_NAME=None,SOFTWARE_IMAGE_MD5_HASH=None):
    """
    Generates device configuration based on enabled features.

    Parameters:
    - enable_features: A dictionary with feature names as keys and boolean values indicating whether the feature is enabled.

    Returns:
    - A string containing the rendered configuration.
    """

    device_specific_feature_templates = {
        # "serial_number_enabled": """ """,
        "hostname_enabled": """cli.configurep(['hostname {}'.format(device_specific_values[serial].get('hostname'))])""",
        "mgmt_v4_ip_enabled": """cli.configurep([f"interface Vlan{mgmt_vlan_number}", "description Mgmt", f"ip address {device_specific_values[serial].get('mgmt_v4_ip')} {device_specific_values[serial].get('mgmt_v4_mask')}", "no ip redirects", "no ip proxy-arp", "no shutdown", "end"])""",
        # "mgmt_v4_mask_enabled": """ """,
        "mgmt_v6_ip_enabled": """cli.configurep([f"interface Vlan{mgmt_vlan_number}", "description Mgmt", f"ipv6 address {device_specific_values[serial].get('mgmt_v6_ip')}/64", "no ip redirects", "no ip proxy-arp", "end"])""",
        "default_gateway_enabled": """cli.configurep([f"ip default-gateway {device_specific_values[serial].get('default_gateway')}", "end"])"""
    }


    # Define the templates for each configurable feature
    feature_templates = {"mgmt_vlan_enabled": """cli.configurep([f"vlan {mgmt_vlan_number}", "name Management", "end"])""",
                         "enable_secret_enabled": """cli.configurep([f"enable secret {device_common_values['enable_secret']}", "end"])""",
                         "domain_name_enabled": """cli.configurep([f"ip domain name {device_common_values['domain_name']}", "end"])""",
                         "username_enabled": """cli.configurep([f"username {device_common_values['username']} privilege 15 secret {device_common_values['user_secret']}", "end"])""",
                         "vty_enabled": """cli.configurep(["line vty 0 15", f"password {device_common_values['vty_password']}", "login", "end"])""",
                         "vtp_enabled": """cli.configurep(["vtp mode server", f"vtp domain {device_common_values['vtp_domain_name']}", f"vtp password {device_common_values['vtp_password']}", "end"])""",
                         "vlan_access_enabled": """cli.configurep([f"interface range {device_common_values['vlan_access_interface_id']}", "switchport mode access", f"switchport access vlan {device_common_values['vlan_access']}", "end"])""",
                         "vlan_trunk_ports_enabled": """cli.configurep([f"interface {device_common_values['vlan_trunk_interface_id']}", "switchport mode trunk", f"switchport trunk allowed vlan {device_common_values['vlan_trunk_ports']}", "end"])""",
                         "dns_servers_enabled": """cli.configurep([f"ip name-server {device_common_values['dns_servers']}", "end"])""",
                         "netflow_collectors_enabled": """cli.configurep([f"flow exporter {device_common_values['netflow_collector_name']}", f"destination {device_common_values['netflow_collector_ip']}", "end"])""",
                         "ntp_servers_enabled": """cli.configurep([f"ntp server {device_common_values['ntp_servers']}", "end"])""",
                         "syslog_servers_enabled": """cli.configurep([f"logging host {device_common_values['syslog_servers']}", "end"])""",
                         "dhcp_snooping_vlans_enabled": """cli.configurep(["ip dhcp snooping", f"ip dhcp snooping vlan {device_common_values['dhcp_snooping_vlans']}", "end"])""",
                         "http_value_enabled": """cli.configurep(["no ip http server", "end"])""",
                         "https_value_enabled": """cli.configurep(["no ip http secure-server", "end"])""",
                         "ssh_value_enabled": """cli.configurep(["crypto key generate rsa general-keys modulus 2048", "ip ssh version 2", "end"])""",
                         "aaa_enabled": """cli.configurep(["aaa new-model"])""",
                         "snmp_enabled": """cli.configurep([f"snmp-server community {device_common_values['snmp_public_community']} RO ipv6 ipv6-snmp-mgmt ipv4-snmp-mgmt", "end"])
cli.configurep([f"snmp-server community {device_common_values['snmp_private_community']} RW ipv6 ipv6-snmp-mgmt ipv4-snmp-mgmt", "end"])
cli.configurep([f"snmp-server trap-source vlan{mgmt_vlan_number}", "end"])
cli.configurep([f"snmp-server host {device_common_values['snmp_server']} version 2c {device_common_values['snmp_password']}", "end"])""",
                         "telnet_enabled": """cli.configurep(["line vty 0 15", "transport output telnet", "end"])"""
                         }

    # Main configuration template
    main_template_str = open("ztp_template.py", "r").read()

    # Further configurations...
    template_variables = {key: "" for key in feature_templates.keys()}

    #Insert enabled device specific feature configurations
    for feature, enabled in enable_device_specific_features.items():
        if enabled and feature in device_specific_feature_templates:
            template_variables[feature] = device_specific_feature_templates[feature]

    # Insert enabled device common feature configurations
    for feature, enabled in enable_features.items():
        if enabled and feature in feature_templates:
            template_variables[feature] = feature_templates[feature]


    if TFTP_SERVER:
        template_variables["TFTP_SERVER"] = TFTP_SERVER
    else:
        raise ValueError("NO TFTP SERVER PROVIDED!")
    
    # Render the main template with the prepared variables
    env = Environment(loader=BaseLoader())
    main_template = env.from_string(main_template_str)
    rendered_output = main_template.render(**template_variables)

    return rendered_output


enabled_features = { "mgmt_vlan_enabled": False,
                     "enable_secret_enabled": False,
                     "domain_name_enabled": False,
                     "username_enabled": False,
                     "vty_enabled": False,
                     "vtp_enabled": False,
                     "vlan_access_enabled": False,
                     "vlan_trunk_ports_enabled": False,
                     "dns_servers_enabled": False,
                     "netflow_collectors_enabled": False,
                     "ntp_servers_enabled": False,
                     "syslog_servers_enabled": False,
                     "dhcp_snooping_vlans_enabled": False,
                     "http_value_enabled": False,
                     "https_value_enabled": False,
                     "ssh_value_enabled": False,
                     "aaa_enabled": False,
                     "snmp_enabled": False}

# print(generate_configuration(enabled_features))

