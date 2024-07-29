# Catalyst_ZTP
Automate Zero Touch Provisioning of multiple Cisco Catalyst Switches

## TFTP Server 
1. Edit "dotenv.txt" file with TFTP Server details:
    * TFTP Server Login Credentials
    * TFTP_USERNAME = "name"
    * TFTP_PASSWORD = "password"
    * TFTP_SERVER = "10.1.1.5"
    * TFTP_SERVER_PATH = "/srv/tftp"

2.  Rename file "dotenv.txt" to ".env"

## Needed Python Package
1.  Pip Install the needed python packages
    * gradio
    * jinja2
    * pandas
    * openpyxl
    * paramiko
    * python-dotenv

## Run the ZTP Gradio script
1. run the python script
    * python ztp_gradio.py

2.  Open web browser and access local gradio server. 
    * IP address and port number will be displayed in the terminal. 

3.  An Excel Template file and the ztp.py script file need to be created.  Use the Template Creator tab in the ZTP Web GUI to create both files.
    * Choose the variables parameters you want to include in the Excel Template file.
    * Click Save Template and a new Excel file will be created with the variables you selected. 
    * The Excel template file and ztp.py file will be created in the "data" subdirectory.  
        * The subdirectory will be created if it doesn't exist.

4.  Add the devices with the variable parameters to the Excel file and save the file.
   
5.  Load the modified Excel Data File in the ZTP Web GUI.
   
6.  Click 'Preview Data' button
    * The Excel data will be converted to the needed python data type.

7.  Click 'Saved and Upload' button
    * Saves a local copy of the converted python data to the local 'data' subdirectory.
    * The python data file and the ztp.py script in the 'data' subdirectory will be upload to the TFTP.
    
