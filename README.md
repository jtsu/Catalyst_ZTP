# Catalyst_ZTP
Automate Zero Touch Provisioning of multiple Cisco Catalyst Switches


1.  Edit "dotenv.txt" file with TFTP Server details:
    TFTP Server Login Credentials
    TFTP_USERNAME = "name"
    TFTP_PASSWORD = "password"
    TFTP_SERVER = "10.1.1.5"
    TFTP_SERVER_PATH = "/srv/tftp"

2.  Rename file "dotenv.txt" to ".env"

3.  Pip Install the needed python packages:
    gradio
    jinja2
    pandas
    openpyxl
    paramiko
    python-dotenv

4.  Run the ztp gradio python script:
    python ztp_gradio.py

5.  Open web browser and access local gradio server. 
    IP address and port number will be displayed in the terminal. 

6.  First time use, an Excel Template and the ztp.py script files need to be created.  
    Use the Template Creator tab in the ZTP Web GUI to create both files.
        Choose the variables parameters you want to include in the Excel Template file.
        Click Save Template and a new Excel file will be created with the variables you selected. 
        The Excel template file and ztp.py file will be created in the "data" subdirectory.  
        The subdirectory will be created if it doesn't exist.

7.  Add the devices with the variable parameters to the Excel file and save the file.
   
8.  Load the modified Excel Data File in the ZTP Web GUI.
   
9.  Click 'Preview Data' and the Excel data will be converted to the needed python data type.

10. Clicking 'Saved and Upload' will save a local copy of the converted python data to the local 'data' subdirectory,
    and the data file and the ztp.py script in the 'data' subdirectory will be upload to the TFTP.
    
