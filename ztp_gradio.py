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

# pip install openpyxl gradio pandas paramiko python-dotenv

import os
import subprocess  # For executing a shell command
import platform  # For getting the operating system name
import gradio as gr
import pandas as pd
import paramiko
from dotenv import load_dotenv
from utils import generate_configuration
from distutils.util import strtobool # Load private variables from .env file
load_dotenv()

# Local Configuration
LOCAL_SAVE_PATH = "./data"
LOCAL_SAVE_FILE = "config_values.py"
LOCAL_SAVE_CONFIG_TEMPLATE = "config_values_template.xlsx"

# TFTP Configuration
TFTP_SERVER = os.getenv("TFTP_SERVER")  # TFTP server IP
TFTP_SERVER_PATH = os.getenv("TFTP_SERVER_PATH")  # Path on the TFTP server
TFTP_USERNAME = os.getenv("TFTP_USERNAME")  # Username in .env file
TFTP_PASSWORD = os.getenv("TFTP_PASSWORD")  # Password in .env file
SOFTWARE_UPGRADE = strtobool(os.getenv("SOFTWARE_UPGRADE")) # Bool value (should the software be ugraded?)
SOFTWARE_IMAGE_FILE_NAME = os.getenv("SOFTWARE_IMAGE_FILE_NAME") # Software image file name
SOFTWARE_IMAGE_MD5_HASH = os.getenv("SOFTWARE_IMAGE_MD5_HASH") # Software image file md5 hash
def meraki_monitoring_changed(meraki_enabled):
    # If Meraki Monitoring is enabled, also enable SSHv2
    if meraki_enabled:
        return True, True, True, True  # Return True to check the SSHv2 checkbox
    else:
        return False, False, False, False
    return ssh_enabled  # Return the current state of the SSHv2 checkbox to avoid changing it if not necessary


def xls_to_dict(xls_file):
    try:
        # Load the first sheet
        excel_sheet1_df = pd.read_excel(xls_file, engine="openpyxl", sheet_name=0)
        # Assuming you want to keep using the serial_number as keys for device_specific_data
        device_specific_data = excel_sheet1_df.set_index("serial_number").to_dict(orient='index')
        device_specific = ' '.join(["device_specific_values = ", str(device_specific_data)])

        # Load the second sheet
        excel_sheet2_df = pd.read_excel(xls_file, engine="openpyxl", sheet_name=1)
        # Convert the entire sheet to a dictionary without using an index_number as keys
        device_common_data_list = excel_sheet2_df.to_dict(orient='records')
        # If there's only one record and you want it as a single dictionary, not a list:
        device_common_data = device_common_data_list[0] if device_common_data_list else {}
        device_common = ' '.join(["device_common_values = ", str(device_common_data)])

        config_values = f"{device_specific}\n\n{device_common}"

        return (excel_sheet1_df, excel_sheet2_df, config_values, gr.Row(visible=True), gr.Button(interactive=True))

    except Exception as e:
        print(e)
        gr.Warning(f"Select an Excel file to load.... exception: {e}")
        return (None, None, None, gr.Row(visible=False), gr.Button(interactive=False))


def save_dict(config_data):
    save_file = '/'.join([LOCAL_SAVE_PATH, LOCAL_SAVE_FILE])
    directory = LOCAL_SAVE_PATH
    if config_data:
        # Ensure directory exists
        if not os.path.exists(LOCAL_SAVE_PATH):
            print(f'Creating directory: {LOCAL_SAVE_PATH}')
            os.makedirs(LOCAL_SAVE_PATH)

        with open(save_file, 'w') as f:
            f.write(config_data)
        try:
            # Check if file was created
            if os.path.isfile(save_file):
                print(f'File saved locally: {save_file}')
                gr.Info(f"File saved locally: {save_file}")

                # Upload file to TFTP server
                # Check if 'data' directory exists to prevent errors
                ztp_file_path = ""
                if os.path.isdir(directory):
                    for item in os.listdir(directory):
                        if item == "ztp.py":
                            ztp_file_path = os.path.join(directory, item)
                if ztp_file_path:
                    upload_tftp([save_file, ztp_file_path])
                else:
                    upload_tftp([save_file])
                return gr.Button(interactive=False)
        except Exception as e:
            gr.Warning(e)
            print(e)
    else:
        gr.Warning("No data to save")
        return (gr.Button(interactive=True))


def clear_file():
    # This function will reset the Save button to interactive=False when the clear_file_button is pressed.
    return (gr.Row(visible=False), gr.Button(interactive=False))


# Set up SCP function
def scp_file(local_path, remote_path):
    # Check if TFTP server is reachable
    ping = ping_test(TFTP_SERVER)
    if ping:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(TFTP_SERVER, username=TFTP_USERNAME, password=TFTP_PASSWORD)
        scp = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
        print("Uploading file(s)...")
        scp.put(local_path, remote_path, confirm=False)
        try:
            # Simple check if file exists on TFTP server
            file_stat = scp.stat(remote_path)
            print(f'File uploaded to: {TFTP_SERVER}:{TFTP_SERVER_PATH}')
            gr.Info(f"File uploaded to {TFTP_SERVER}:{TFTP_SERVER_PATH}")
        except Exception as e:
            print(e)
            gr.Warning(e)
        finally:
            scp.close()
            ssh_client.close()
    else:
        print(f"Unable to ping {TFTP_SERVER}")
        gr.Warning(f"Unable to ping {TFTP_SERVER}.  Please check your network connection.  Upload aborted.")


def upload_tftp(files):
    try:
        print(f'uploading file: {files}')
        for file in files:
            remote_file_path = os.path.join(TFTP_SERVER_PATH, os.path.basename(file))

            scp_file(file, remote_file_path)
        return (f"Uploaded {len(files)} files to {TFTP_SERVER}:{TFTP_SERVER_PATH}")
    except Exception as e:
        print(e)
        return (e)


def ping_test(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '2', host]

    return subprocess.call(command) == 0


def excel_template(device_specific, device_common):
    # device_specific = ["serial_number"] + device_specific

    df_device_specific = pd.DataFrame(columns=device_specific)
    df_device_common = pd.DataFrame(device_common, index=[device_common['index_number']])

    save_file = '/'.join([LOCAL_SAVE_PATH, LOCAL_SAVE_CONFIG_TEMPLATE])
    try:
        # Ensure directory exists
        if not os.path.exists(LOCAL_SAVE_PATH):
            print(f'Creating directory: {LOCAL_SAVE_PATH}')
            os.makedirs(LOCAL_SAVE_PATH)

        with pd.ExcelWriter(save_file) as writer:
            df_device_specific.to_excel(writer, sheet_name='device_specific', index=False)
            df_device_common.to_excel(writer, sheet_name='device_common', index=False)
            gr.Info(f"Excel template created: {save_file}")
    except Exception as e:
        print(e)
        gr.Warning(e)


def testbox_visible(checkbox_enabled):
    if checkbox_enabled:
        return (gr.Textbox(visible=True))
    else:
        return (gr.Textbox(visible=False))


def column_visible(checkbox_enabled):
    if checkbox_enabled:
        return (gr.Column(visible=True))
    else:
        return (gr.Column(visible=False))


def row_visible(checkbox_enabled):
    if checkbox_enabled:
        return (gr.Row(visible=True))
    else:
        return (gr.Row(visible=False))


# This function is triggered when the SSHv2 checkbox is toggled.
def on_sshv2_change(ssh_enabled, *args):
    # Check if ssh_enabled is True, then enable other options
    if ssh_enabled:
        return True, True  # Return True for domain_name_enabled, username_enabled, enable_secret_enabled
    else:
        # Optionally, handle the case when ssh is disabled, depending on your requirements
        return False, False

def on_checkbox_column_visible_change(checkbox_enabled):
    visible_column = column_visible(checkbox_enabled)
    if checkbox_enabled:
        return visible_column, True
    else:
        return visible_column, False


def main():
    css = """
    h1 {
        text-align: left;
        vertical-align: center;
        display: block;
    }
    img{
        width: 80px;
        height: 80px;
        float: right;
        vertical-align: center;
        display: block;

    }
    footer {visibility: hidden}
    """

    with gr.Blocks(title=" Cisco ZTP", css=css) as convert_data:
        # Row for Title and Logo
        with gr.Row():
            with gr.Column(scale=3):
                gr.Markdown("""
                    # Cisco ZTP Configuration Tool
                    """
                            )
            with gr.Column(scale=1):
                logo = (os.path.join(os.path.dirname(__file__), "cisco-meraki-logo.webp"))
                gr.Image(logo, show_label=False, show_download_button=False, container=False)

        # Tab 1
        with gr.Tab("Load Excel Data"):
            gr.Markdown(
                """
                ### Convert Excel data and upload to TFTP Server.
                """
            )

            with gr.Row():
                load_file = gr.File(label="Select Excel File", file_count="single", file_types=[".xlsx", ".xls"])

            with gr.Row(visible=False) as preview_row:
                excel_sheet0_df = gr.DataFrame(label="Device Specific Variables", type="pandas", height=320)
                excel_sheet1_df = gr.DataFrame(label="Device Common Variables", type="pandas", height=320)
                config_values = gr.Textbox(
                    label="Config Variables",
                    lines=2,
                    max_lines=13,
                    placeholder="Variables required for ZTP Configuration"
                )

            with gr.Row():
                preview_button_tab1 = gr.Button("Preview Data")
                save_file_button_tab1 = gr.Button("Save and Upload File", interactive=False)
                clear_file_button_tab1 = gr.ClearButton([load_file, excel_sheet0_df, excel_sheet1_df, config_values],
                                                        "Reset")

        # Tab 2
        with gr.Tab("Upload Files to TFTP Server"):
            gr.Markdown(
                """
                ### Uploads py file(s) to your TFTP server.
                """
            )
            with gr.Row():
                upload_file = gr.File(label="Load File", file_count="multiple")
            with gr.Row():
                upload_output = gr.Textbox(label="TFTP Upload Status")
            with gr.Row():
                upload_button_tab2 = gr.Button("Upload")
                clear_upload_file_tab2 = gr.ClearButton(upload_file, "Clear")

        preview_button_tab1.click(xls_to_dict, inputs=load_file,
                                  outputs=[excel_sheet0_df, excel_sheet1_df, config_values, preview_row,
                                           save_file_button_tab1])
        save_file_button_tab1.click(save_dict, inputs=config_values, outputs=[save_file_button_tab1])
        clear_file_button_tab1.click(clear_file, inputs=None, outputs=[preview_row, save_file_button_tab1])
        upload_button_tab2.click(upload_tftp, inputs=upload_file, outputs=upload_output)

        # Tab 3
        with gr.Tab("Template Creator"):
            gr.Markdown(
                """
                ### The template creator can be used to help collect device specific values that are \
                needed for each device, and common values that will be configured on all devices.  \
                An Excel template file can be created to collect device specific values, and the \
                common values to be configured on all devices can be entered in the form below.
                """
            )
            with gr.Accordion("Device Specific Values"):
                gr.Markdown(
                    """
                    ### Select the device specific values to be create in the Excel template file.
                    """
                )

                # Checkboxes used for created device specific variables sheet in Excel template
                device_serial_number = gr.CheckboxGroup(
                    choices=["serial_number"],
                    value=["serial_number"],
                    label="Device required values",
                    info="The serial number is required to identify the device.",
                    interactive=False
                )
                device_specific_vars = gr.CheckboxGroup(
                    choices=["hostname", "mgmt_v4_ip", "mgmt_v4_mask", "mgmt_v6_ip", "default_gateway"],
                    value=["hostname", "mgmt_v4_ip", "mgmt_v4_mask", "mgmt_v6_ip", "default_gateway"],
                    label="Device Specific Variables",
                    info="These variables are unique each specific device.",
                    interactive=True
                )

            with gr.Accordion("Device Common Values"):
                gr.Markdown(
                    """
                    ### Select the features to enabled and enter the values.
                    """
                )
                # Checkboxes and Textboxes for Tab 3 Common value variables
                with gr.Row():
                    with gr.Column():
                        with gr.Row():
                            mgmt_vlan_enabled = gr.Checkbox(label="Mgmt VLAN", interactive=True, value=False)
                        with gr.Row(visible=False) as mgmt_vlan_row:
                            mgmt_vlan = gr.Textbox(label="Mgmt VLAN", placeholder="100", type="text", interactive=True,
                                                   visible=True)
                    with gr.Column():
                        with gr.Row():
                            enable_secret_enabled = gr.Checkbox(label="Enable Secret", interactive=True, value=False)
                        with gr.Row(visible=False) as enable_secret_row:
                            enable_secret = gr.Textbox(label="Enable Secret", placeholder="cisco", type="text",
                                                       interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            domain_name_enabled = gr.Checkbox(label="Domain Name", interactive=True, value=False)
                        with gr.Row(visible=False) as domain_name_row:
                            domain_name = gr.Textbox(label="Domain Name", placeholder="example.com", type="text",
                                                     interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            username_enabled = gr.Checkbox(label="Username", interactive=True, value=False)
                        with gr.Row(visible=False) as username_row:
                            username = gr.Textbox(label="Username", placeholder="username", type="text",
                                                  interactive=True, visible=True)
                            user_secret = gr.Textbox(label="User Secret", placeholder="secret", type="text",
                                                     interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            vty_enabled = gr.Checkbox(label="VTY Password", interactive=True, value=False)
                        with gr.Row(visible=False) as vty_row:
                            vty_password = gr.Textbox(label="VTY Password", placeholder="vty_password", type="text",
                                                      interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            vtp_enabled = gr.Checkbox(label="VTP Enabled", interactive=True, value=False)
                        with gr.Row(visible=False) as vtp_row:
                            vtp_domain_name = gr.Textbox(label="VTP Domain Name", placeholder="vtp_domain", type="text",
                                                         interactive=True, visible=True)
                            vtp_password = gr.Textbox(label="VTP Password", placeholder="vtp_password", type="text",
                                                      interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            vlan_access_enabled = gr.Checkbox(label="VLAN Access", interactive=True, value=False)
                        with gr.Row(visible=False) as vlan_access_row:
                            vlan_access_interface_id = gr.Textbox(label="Access VLAN Interface/range", placeholder="GigabitEthernet1/0/1",
                                                     type="text", interactive=True, visible=True)
                            vlan_access = gr.Textbox(label="Access VLAN Numbers", placeholder="100-110, 200",
                                                     type="text", interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            vlan_trunk_ports_enabled = gr.Checkbox(label="VLAN Trunk", interactive=True, value=False)
                        with gr.Row(visible=False) as vlan_trunk_ports_row:
                            vlan_trunk_interface_id = gr.Textbox(label="Trunk Interface/range",
                                                                 placeholder="GigabitEthernet1/0/1",
                                                                 type="text", interactive=True, visible=True)
                            vlan_trunk_ports = gr.Textbox(label="Trunk allowed vlans", placeholder="10,20,50,100", type="text",
                                                          interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            dns_servers_enabled = gr.Checkbox(label="DNS Servers", interactive=True, value=False)
                        with gr.Row(visible=False) as dns_servers_row:
                            dns_servers = gr.Textbox(label="DNS Servers", placeholder="208.67.222.222, 208.67.220.220",
                                                     type="text", interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            netflow_collectors_enabled = gr.Checkbox(label="Netflow Collectors", interactive=True,
                                                                     value=False)
                        with gr.Row(visible=False) as netflow_collectors_row:
                            netflow_collector_name = gr.Textbox(label="Netflow Collector Name",
                                                                placeholder="CollectorName",
                                                                type="text", interactive=True, visible=True)

                            netflow_collectors = gr.Textbox(label="Netflow Collector IP Address", placeholder="10.2.1.1",
                                                            type="text", interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            ntp_servers_enabled = gr.Checkbox(label="NTP Servers", interactive=True, value=False)
                        with gr.Row(visible=False) as ntp_servers_row:
                            ntp_servers = gr.Textbox(label="NTP Servers", placeholder="10.3.1.1", type="text",
                                                     interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            syslog_servers_enabled = gr.Checkbox(label="Syslog Servers", interactive=True, value=False)
                        with gr.Row(visible=False) as syslog_servers_row:
                            syslog_servers = gr.Textbox(label="Syslog Servers", placeholder="10.4.1.1,10.4.1.2",
                                                        type="text", interactive=True, visible=True)
                    with gr.Column():
                        with gr.Row():
                            dhcp_snooping_vlans_enabled = gr.Checkbox(label="DHCP Snooping", interactive=True,
                                                                      value=False)
                        with gr.Row(visible=False) as dhcp_snooping_vlans_row:
                            dhcp_snooping_vlans = gr.Textbox(label="DHCP Snooping VLANs", placeholder="100, 200",
                                                             type="text", interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            http_value_enabled = gr.Checkbox(label="No HTTP Enabled", interactive=True, value=False)
                    with gr.Column():
                        https_value_enabled = gr.Checkbox(label="No HTTPS Enabled", interactive=True, value=False)
                    with gr.Column():
                        ssh_value_enabled = gr.Checkbox(label="SSHv2 Enabled", interactive=True, value=False)
                    with gr.Column():
                        with gr.Row():
                            telnet_value_enabled = gr.Checkbox(
                                label="Telnet Enabled", interactive=True, value=False)
                    with gr.Column():
                        with gr.Row():
                            meraki_catalyst_monitoring_value_enabled = gr.Checkbox(
                                label="Meraki Catalyst Monitoring Enabled", interactive=True, value=False)

                    with gr.Column():
                        with gr.Row():
                            aaa_enabled = gr.Checkbox(label="AAA Enabled", interactive=True, value=False)
                        # with gr.Row(visible=False) as aaa_row:
                        #     aaa_servers = gr.Textbox(label="AAA Server IP Addresses", placeholder="10.1.1.1, 10.1.1.2",
                        #                              type="text", interactive=True, visible=True)
                        #     aaa_key = gr.Textbox(label="AAA Key", placeholder="aaa_server_key", type="text",
                        #                          interactive=True, visible=True)
                        #     aaa_group = gr.Textbox(label="AAA Group", placeholder="AAA Group Name", type="text",
                        #                            interactive=True, visible=True)
                        #     aaa_profile = gr.Textbox(label="AAA Profile", placeholder="AAA Profile Name", type="text",
                        #                              interactive=True, visible=True)

                    with gr.Column():
                        with gr.Row():
                            snmp_enabled = gr.Checkbox(label="SNMP Enabled", interactive=True, value=False)
                        with gr.Row(visible=False) as snmp_row:
                            snmp_public_community = gr.Textbox(label="SNMP Public Community", placeholder="public",
                                                               type="text", interactive=True, visible=True)
                            snmp_private_community = gr.Textbox(label="SNMP Private Community", placeholder="private",
                                                                type="text", interactive=True, visible=True)
                            snmp_server = gr.Textbox(label="SNMP Servers", placeholder="10.5.1.1",
                                                      type="text", interactive=True, visible=True)
                            snmp_password = gr.Textbox(label="SNMP Password", placeholder="snmp_password",
                                                       type="text", interactive=True, visible=True)
                # Example of defining the instruction output component
                instruction_output = gr.Markdown()

                # Check for changed in checkbox and change visibility of textbox rows
                mgmt_vlan_enabled.change(column_visible, inputs=[mgmt_vlan_enabled], outputs=[mgmt_vlan_row])
                enable_secret_enabled.change(column_visible, inputs=[enable_secret_enabled],
                                             outputs=[enable_secret_row])
                domain_name_enabled.change(column_visible, inputs=[domain_name_enabled], outputs=[domain_name_row])
                username_enabled.change(column_visible, inputs=[username_enabled], outputs=[username_row])
                vty_enabled.change(column_visible, inputs=[vty_enabled], outputs=[vty_row])
                vtp_enabled.change(column_visible, inputs=[vtp_enabled], outputs=[vtp_row])
                vlan_access_enabled.change(column_visible, inputs=[vlan_access_enabled], outputs=[vlan_access_row])
                vlan_trunk_ports_enabled.change(column_visible, inputs=[vlan_trunk_ports_enabled],
                                                outputs=[vlan_trunk_ports_row])
                dns_servers_enabled.change(column_visible, inputs=[dns_servers_enabled], outputs=[dns_servers_row])
                netflow_collectors_enabled.change(column_visible, inputs=[netflow_collectors_enabled],
                                                  outputs=[netflow_collectors_row])
                ntp_servers_enabled.change(column_visible, inputs=[ntp_servers_enabled], outputs=[ntp_servers_row])
                syslog_servers_enabled.change(column_visible, inputs=[syslog_servers_enabled],
                                              outputs=[syslog_servers_row])
                dhcp_snooping_vlans_enabled.change(column_visible, inputs=[dhcp_snooping_vlans_enabled],
                                                   outputs=[dhcp_snooping_vlans_row])
                # aaa_enabled.change(column_visible, inputs=[aaa_enabled], outputs=[aaa_row])
                snmp_enabled.change(column_visible, inputs=[snmp_enabled], outputs=[snmp_row])
                ssh_value_enabled.change(
                    on_sshv2_change,
                    inputs=[ssh_value_enabled],
                    outputs=[domain_name_enabled, username_enabled]
                )
                meraki_catalyst_monitoring_value_enabled.change(
                    meraki_monitoring_changed,  # This function needs to be defined elsewhere
                    inputs=[meraki_catalyst_monitoring_value_enabled],
                    # Now it's okay to use it here
                    outputs=[ssh_value_enabled, aaa_enabled, ntp_servers_enabled, telnet_value_enabled]
                )

                # Clear checkboxes and textfields in Tab 3
                with gr.Row():
                    device_save_button_tab3 = gr.Button("Save Template")
                    device_clear_button_tab3 = gr.ClearButton([
                        device_specific_vars,
                        mgmt_vlan_enabled,
                        mgmt_vlan,
                        enable_secret_enabled,
                        enable_secret,
                        domain_name_enabled,
                        domain_name,
                        username_enabled,
                        username,
                        user_secret,
                        vty_enabled,
                        vty_password,
                        vtp_enabled,
                        vtp_domain_name,
                        vtp_password,
                        vlan_access_enabled,
                        vlan_access,
                        vlan_access_interface_id,
                        vlan_trunk_ports_enabled,
                        vlan_trunk_ports,
                        vlan_trunk_interface_id,
                        dns_servers_enabled,
                        dns_servers,
                        netflow_collectors_enabled,
                        netflow_collectors,
                        netflow_collector_name,
                        ntp_servers_enabled,
                        ntp_servers,
                        syslog_servers_enabled,
                        syslog_servers,
                        dhcp_snooping_vlans_enabled,
                        dhcp_snooping_vlans,
                        http_value_enabled,
                        https_value_enabled,
                        ssh_value_enabled,
                        meraki_catalyst_monitoring_value_enabled,
                        aaa_enabled,
                        # aaa_servers,
                        # aaa_key, aaa_group,
                        # aaa_profile,
                        snmp_enabled,
                        snmp_public_community,
                        snmp_private_community,
                        snmp_server,
                        snmp_password,
                        telnet_value_enabled
                    ],
                        "Clear Device Common Values")

                def get_common_features(input):
                    #device_specific = input[device_specific_vars]
                    device_specific = input[device_serial_number] + input[device_specific_vars]

                    enabled_device_specific_features = {
                        'serial_number_enabled': False,
                        'hostname_enabled': False,
                        'mgmt_v4_ip_enabled': False,
                        'mgmt_v4_mask_enabled': False,
                        'mgmt_v6_ip_enabled': False,
                        'default_gateway_enabled': False
                    }
                    if 'serial_number' in device_specific:
                        enabled_device_specific_features['serial_number_enabled'] = True
                    if 'hostname' in device_specific:
                        enabled_device_specific_features['hostname_enabled'] = True
                    if 'mgmt_v4_ip' in device_specific:
                        enabled_device_specific_features['mgmt_v4_ip_enabled'] = True
                    if 'mgmt_v4_mask' in device_specific:
                        enabled_device_specific_features['mgmt_v4_mask_enabled'] = True
                    if 'mgmt_v6_ip' in device_specific:
                        enabled_device_specific_features['mgmt_v6_ip_enabled'] = True
                    if 'default_gateway' in device_specific:    
                        enabled_device_specific_features['default_gateway_enabled'] = True
                    # print(enabled_device_specific_features)

                    device_common = {'index_number': 0}
                    enabled_features = {"mgmt_vlan_enabled": False,
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
                                        "snmp_enabled": False,
                                        "telnet_enabled": False}


                    if input[mgmt_vlan_enabled]:
                        enabled_features["mgmt_vlan_enabled"] = True
                        device_common["mgmt_vlan_enabled"] = input[mgmt_vlan_enabled]
                        device_common["mgmt_vlan"] = input[mgmt_vlan]
                    if input[enable_secret_enabled]:
                        enabled_features["enable_secret_enabled"] = True
                        device_common["enable_secret_enabled"] = input[enable_secret_enabled]
                        device_common["enable_secret"] = input[enable_secret]
                    if input[domain_name_enabled]:
                        enabled_features["domain_name_enabled"] = True
                        device_common["domain_name_enabled"] = input[domain_name_enabled]
                        device_common["domain_name"] = input[domain_name]
                    if input[username_enabled]:
                        enabled_features["username_enabled"] = True
                        device_common["username_enabled"] = input[username_enabled]
                        device_common["username"] = input[username]
                        device_common["user_secret"] = input[user_secret]
                    if input[vty_enabled]:
                        enabled_features["vty_enabled"] = True
                        device_common["vty_enabled"] = input[vty_enabled]
                        device_common["vty_password"] = input[vty_password]
                    if input[vtp_enabled]:
                        enabled_features["vtp_enabled"] = True
                        device_common["vtp_enabled"] = input[vtp_enabled]
                        device_common["vtp_domain_name"] = input[vtp_domain_name]
                        device_common["vtp_password"] = input[vtp_password]
                    if input[vlan_access_enabled]:
                        enabled_features["vlan_access_enabled"] = True
                        device_common["vlan_access_enabled"] = input[vlan_access_enabled]
                        device_common["vlan_access"] = input[vlan_access]
                        device_common["vlan_access_interface_id"] = input[vlan_access_interface_id]
                    if input[vlan_trunk_ports_enabled]:
                        enabled_features["vlan_trunk_ports_enabled"] = True
                        device_common["vlan_trunk_ports_enabled"] = input[vlan_trunk_ports_enabled]
                        device_common["vlan_trunk_ports"] = input[vlan_trunk_ports]
                        device_common['vlan_trunk_interface_id'] = input[vlan_trunk_interface_id]
                    if input[dns_servers_enabled]:
                        enabled_features["dns_servers_enabled"] = True
                        device_common["dns_servers_enabled"] = input[dns_servers_enabled]
                        device_common["dns_servers"] = input[dns_servers]
                    if input[netflow_collectors_enabled]:
                        enabled_features["netflow_collectors_enabled"] = True
                        device_common["netflow_collectors_enabled"] = input[netflow_collectors_enabled]
                        device_common['netflow_collector_name'] = input[netflow_collector_name]
                        device_common["netflow_collector_ip"] = input[netflow_collectors]
                    if input[ntp_servers_enabled]:
                        enabled_features["ntp_servers_enabled"] = True
                        device_common["ntp_servers_enabled"] = input[ntp_servers_enabled]
                        device_common["ntp_servers"] = input[ntp_servers]
                    if input[syslog_servers_enabled]:
                        enabled_features["syslog_servers_enabled"] = True
                        device_common["syslog_servers_enabled"] = input[syslog_servers_enabled]
                        device_common["syslog_servers"] = input[syslog_servers]
                    if input[dhcp_snooping_vlans_enabled]:
                        enabled_features["dhcp_snooping_vlans_enabled"] = True
                        device_common["dhcp_snooping_vlans_enabled"] = input[dhcp_snooping_vlans_enabled]
                        device_common["dhcp_snooping_vlans"] = input[dhcp_snooping_vlans]
                    if input[http_value_enabled]:
                        enabled_features["http_value_enabled"] = True
                        device_common["http_value_enabled"] = input[http_value_enabled]
                    if input[https_value_enabled]:
                        enabled_features["https_value_enabled"] = True
                        device_common["https_value_enabled"] = input[https_value_enabled]
                    if input[ssh_value_enabled]:
                        enabled_features["ssh_value_enabled"] = True
                        device_common["ssh_value_enabled"] = input[ssh_value_enabled]
                    if input[meraki_catalyst_monitoring_value_enabled]:
                        device_common["meraki_catalyst_monitoring_value_enabled"] = input[
                            meraki_catalyst_monitoring_value_enabled]
                    if input[aaa_enabled]:
                        enabled_features["aaa_enabled"] = True
                        device_common["aaa_enabled"] = input[aaa_enabled]
                        # device_common["aaa_servers"] = input[aaa_servers]
                        # device_common["aaa_key"] = input[aaa_key]
                        # device_common["aaa_group"] = input[aaa_group]
                        # device_common["aaa_profile"] = input[aaa_profile]
                    if input[snmp_enabled]:
                        enabled_features["snmp_enabled"] = True
                        device_common["snmp_enabled"] = input[snmp_enabled]
                        device_common["snmp_public_community"] = input[snmp_public_community]
                        device_common["snmp_private_community"] = input[snmp_private_community]
                        device_common["snmp_server"] = input[snmp_server]
                        device_common["snmp_password"] = input[snmp_password]
                    if input[telnet_value_enabled]:
                        enabled_features["telnet_enabled"] = True
                        device_common["telnet_enabled"] = input[telnet_value_enabled]

                    # Check for missing values
                    missing_values = []
                    for key, value in device_common.items():
                        if device_common[key] == "":
                            missing_values.append(key)

                    if len(missing_values) > 0:
                        gr.Warning(f"The following fields have no value: {missing_values}")
                    else:
                        excel_template(device_specific, device_common)
                        with open("./data/ztp.py", "w") as f:
                            f.write(generate_configuration(enable_device_specific_features=enabled_device_specific_features, enable_features=enabled_features, TFTP_SERVER=TFTP_SERVER, SOFTWARE_UPGRADE=SOFTWARE_UPGRADE, SOFTWARE_IMAGE_MD5_HASH=SOFTWARE_IMAGE_MD5_HASH, SOFTWARE_IMAGE_FILE_NAME=SOFTWARE_IMAGE_FILE_NAME))


                device_save_button_tab3.click(
                    get_common_features,
                    inputs={
                        device_serial_number,
                        device_specific_vars,
                        mgmt_vlan_enabled,
                        mgmt_vlan,
                        enable_secret_enabled,
                        enable_secret,
                        domain_name_enabled,
                        domain_name,
                        username_enabled,
                        username,
                        user_secret,
                        vty_enabled,
                        vty_password,
                        vtp_enabled,
                        vtp_domain_name,
                        vtp_password,
                        vlan_access_enabled,
                        vlan_access,
                        vlan_access_interface_id,
                        vlan_trunk_ports_enabled,
                        vlan_trunk_ports,
                        vlan_trunk_interface_id,
                        dns_servers_enabled,
                        dns_servers,
                        netflow_collectors_enabled,
                        netflow_collectors,
                        netflow_collector_name,
                        ntp_servers_enabled,
                        ntp_servers,
                        syslog_servers_enabled,
                        syslog_servers,
                        dhcp_snooping_vlans_enabled,
                        dhcp_snooping_vlans,
                        http_value_enabled,
                        https_value_enabled,
                        ssh_value_enabled,
                        meraki_catalyst_monitoring_value_enabled,
                        aaa_enabled,
                        # aaa_servers,
                        # aaa_key, aaa_group,
                        # aaa_profile,
                        snmp_enabled,
                        snmp_public_community,
                        snmp_private_community,
                        snmp_server,
                        snmp_password,
                        telnet_value_enabled
                    },
                    outputs=None
                )

    convert_data.launch(share=False)


if __name__ == "__main__":
    main()
