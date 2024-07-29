# Catalyst_ZTP
Automate Zero Touch Provisioning of multiple Cisco Catalyst Switches


## More information on Cisco Zero Touch Provisioning
* https://developer.cisco.com/docs/ios-xe/zero-touch-provisioning/#zero-touch-provisioning


## Required Services
The ZTP script will require the following services from the network
* DHCP Server with DHCP Option 150 and 67 will need to be configured
* TFTP Server details and credientials need to be provided


## TFTP Server information for ZTP script
1. Edit "dotenv.txt" file with TFTP Server details:
    * TFTP Server Login Credentials
    * TFTP_USERNAME = "name"
    * TFTP_PASSWORD = "password"
    * TFTP_SERVER = "10.1.1.5"
    * TFTP_SERVER_PATH = "/srv/tftp"

2.  Rename file "dotenv.txt" to ".env"


## Install the needed Python Package
1.  Pip install the following Python Packages:
    * gradio
    * jinja2
    * pandas
    * openpyxl
    * paramiko
    * python-dotenv


## Using the ZTP Gradio script
1. Run the python script
    * python ztp_gradio.py

2.  Open web browser and access local gradio server. 
    * IP address and port number will be displayed in the terminal.
    * ![gradio_url](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/gradio_url.png?raw=true)

3.  An Excel Template file and the ztp.py script file need to be created.
    * Use the Template Creator tab in the ZTP Web GUI to create the files.
    ![template_creator](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/template_creator.png?raw=true)
    * Choose the variables parameters you want to include in the Excel Template file.
    * Click Save Template and a new Excel file will be created with the variable parameter selected. 
    * The Excel template file and ztp.py file will be created in the 'data' subdirectory.
      ![gradio_url](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/data_subdir.png?raw=true)
        * The 'data' subdirectory will be created if it doesn't exist.

4.  Add the devices with the variable parameters to the Excel file and save the file.
   * Variable parameters that are unique for each device will be in the Device Specific Worksheet tab.    
   ![gradio_url](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/excel_specific.png?raw=true)
   * Variable paramters that are common to multiple devices will be in the Device Common Worksheet tab.
    ![gradio_url](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/excel_common.png?raw=true)
  
5.  Load the modified Excel Data File in the ZTP Web GUI.
    ![load_data](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/load_data.png?raw=true)
   
6.  Click 'Preview Data' button
    * The Excel data will be converted to the needed python data type.

7.  Click 'Saved and Upload' button
    * Saves a local copy of the converted python data to the local 'data' subdirectory.
    * The python data file and the ztp.py script in the 'data' subdirectory will be upload to the TFTP.
    ![gradio_url](https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/data_subdir2.png?raw=true)


## Acknowledgements
Huge thank you to Charles Llewellyn from the Cisco GVE Devnet team for all his hard work, partnership, and support creating this script.

