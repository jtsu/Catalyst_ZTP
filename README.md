# Catalyst_ZTP
Zero-Touch Provisioning automates the process of configuring Cisco Catalyst Switches that are added in your network for the first time. The Catalyst ZTP script simplifies the creation and deployment of ZTP, making it easier to setup multiple devices at scale during the initial deployment.

Check out Cisco DevNet for more information on Cisco Zero Touch Provisioning.
* https://developer.cisco.com/docs/ios-xe/zero-touch-provisioning/#zero-touch-provisioning


# Required Services
The ZTP script will require the following services from the network
* DHCP Server with DHCP Option 150 and 67 will need to be configured
   * option tftp-server-name "10.1.1.5";
   * option bootfile-name "ztp.py";
* TFTP Server details and credientials need to be provided
  1. Edit "dotenv.txt" file with TFTP Server details:
      * TFTP Server Login Credentials
      * TFTP_USERNAME = "name"
      * TFTP_PASSWORD = "password"
      * TFTP_SERVER = "10.1.1.5"
      * TFTP_SERVER_PATH = "/srv/tftp"
  
  2.  Rename file "dotenv.txt" to ".env"


# Install the needed Python Package
1.  Pip install the following Python Packages:
    * gradio
    * jinja2
    * pandas
    * openpyxl
    * paramiko
    * python-dotenv


# Using the ZTP Gradio script
1. Run the python script
    * python ztp_gradio.py

2.  Open web browser and access local gradio server. 
    * IP address and port number will be displayed in the terminal
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/gradio_url.png" height="70">

3.  An Excel Template file and the ztp.py script file need to be created.
    * Use the Template Creator tab in the ZTP Web GUI to create the files.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/template_creator.png" height="400">
    * Choose the variables parameters you want to include in the Excel Template file.
       * Variable parameters that are unique for each device are the Device Specific variables.
          * The template creator will create column headers for the selected device specific variables, but the devices unique variables should be added to the Excel spreadsheet after the template is created. 
       * Variable parameters that are common to multiple devices are the Device Common variables.
          * These variables should be added using the web forms in the template creator.
          * The template creator will add your devices common variables to a separate worksheet in the excel template file.
    * Click the 'Save Template' button and a new Excel file will be created with the selected variable parameters. 
    * The Excel template file and ztp.py file will be created in the 'data' subdirectory.
       * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/data_subdir.png" height="200">
       * The 'data' subdirectory will be created if it doesn't exist.
       * ztp.py is the python script that will be executed during the onboarding process with ZTP.
       * ztp.py is automatically generated by the ZTP Gradio App based on the features and variables selected in the template creator.


4.  Add the devices with the variable parameters to the Excel file and save the file.
    * Variable parameters that are unique for each device will be in the Device Specific Worksheet tab.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/excel_specific.png" height="200">
    * Variable paramters that are common to multiple devices will be in the Device Common Worksheet tab.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/excel_common.png" height="200">
  
5.  Load the modified Excel Data File in the ZTP Web GUI.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/load_data.png" height="200">
6.  Click 'Preview Data' button
    * The Excel data will be converted to the needed python data type.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/data_loaded.png" height="200">

7.  Click 'Saved and Upload' button
    * Saves a local copy of the converted python data to the local 'data' subdirectory.
    * The python data file and the ztp.py script in the 'data' subdirectory will be upload to the TFTP.
    * <img src="https://github.com/jtsu/Catalyst_ZTP/blob/main/Screenshots/data_subdir2.png" height="70">

# Acknowledgements
Huge thank you to Charles Llewellyn from the Cisco GVE Devnet team for all his hard work, partnership, and support creating this script.

