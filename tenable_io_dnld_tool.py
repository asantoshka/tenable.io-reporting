import requests, os
from tabulate import tabulate
import time, datetime
import pandas as pd
import subprocess
from dotenv import load_dotenv

load_dotenv()

if os.getenv('APIKEY') is None:
    print("API keys are not configured.")
    access_key = input("Enter the Access key in below format: ")
    secret_key = input("Enter the Secret key in below format: ")
    KEY = "APIKEY = accessKey=" + access_key + ";" + "secretKey=" + secret_key
    with open('.env', 'w') as f:
        f.write(KEY)

# Update the below values in .env file or here as per the requirement

#------

sender = os.getenv('SENDER')
cc = os.getenv('CC')
subject = "'Vulnerability scan report'"
smtp = os.getenv('SMTP')
body = '''"Hello, 

Please find the attached scan report.

Thanks,
Vulnerability Management Team

"'''
#------

banner = '''
████████ ███████ ███    ██  █████  ██████  ██      ███████     ██  ██████      
   ██    ██      ████   ██ ██   ██ ██   ██ ██      ██          ██ ██    ██     
   ██    █████   ██ ██  ██ ███████ ██████  ██      █████       ██ ██    ██     
   ██    ██      ██  ██ ██ ██   ██ ██   ██ ██      ██          ██ ██    ██     
   ██    ███████ ██   ████ ██   ██ ██████  ███████ ███████     ██  ██████                                                                        
'''
print(banner)

folder_url = "https://cloud.tenable.com/folders"

today = datetime.datetime.now()

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": os.getenv('APIKEY')
}


def download_asset_report():
    print("Downloading the workbench report...")
    workbench_export_url = "https://cloud.tenable.com/workbenches/export?format=csv&report=vulnerabilities&chapter=vuln_by_plugin"
    workbench_export_response = requests.request("GET", workbench_export_url, headers=headers).json()

    workbench_file_id = str(workbench_export_response["file"])
    workbench_export_status_response_url = "https://cloud.tenable.com/workbenches/export/" + workbench_file_id + "/status"

    while True:
        workbench_export_status_response = requests.request("GET", workbench_export_status_response_url, headers=headers).json()
        if workbench_export_status_response["status"] == "ready":
            print("The file is exported.")
            break
        else:
            print("Exporting...waiting for 10 seconds")
            time.sleep(10) 

    workbench_download_url = "https://cloud.tenable.com/workbenches/export/" + workbench_file_id + "/download"

    workbench_download_headers = {
        "Accept": "application/octet-stream",
        "X-ApiKeys": os.getenv('APIKEY')  
    }
    workbench_download_response = requests.request("GET", workbench_download_url, headers=workbench_download_headers)

    open("workbench.csv", 'wb').write(workbench_download_response.content)
    print("File is downloaded")

    print("Foramatting the report")
    workbench_read_file = pd.read_csv("workbench.csv")
    workbench_read_file.drop('See Also', inplace=True, axis=1)
    workbench_read_file.to_excel (r'workbench_report.xlsx', sheet_name="Raw", index = None, header=True)
    os.remove("workbench.csv")

def get_asset_report():
    filepath = "./workbench_report.xlsx"
    if os.path.exists("./workbench_report.xlsx"):
        mtime = os.path.getmtime(filename=filepath) # File modified time
        ctime = time.time() # Current time
        dtime = ctime - mtime # file age

        if dtime <= 3600:
            switch = input("The report containing ageing information is not very old. Do you want a fresh download(y/n): ")
            if switch == 'y'  or switch == 'Y':
                download_asset_report()
            else:
                pass
        else:
            download_asset_report()  
    else:
        download_asset_report()

def noFeature():
    print("This feature is not added yet. Try another ID.")

def folders():
    response_folder = requests.request("GET", folder_url, headers=headers).json()
    folders_list = []

    for folder in response_folder["folders"]:
        folder_data = [folder["name"], folder["id"]]
        folders_list.append(folder_data)

    print(tabulate(folders_list, headers=["Folder Name", "Folder ID"]))

def scans(folder_id):
    scan_url = "https://cloud.tenable.com/scans"
    querystring = {"folder_id":int(folder_id)}

    response_scan_data = requests.request("GET", scan_url, headers=headers, params=querystring).json()

    scans_list = [["All the scans","0000"]]
    for scan in response_scan_data["scans"]:
        scan_data = [scan["name"],scan["id"]]
        scans_list.append(scan_data)
    print(tabulate(scans_list, headers=["Scan name", "Scan ID"]))
    return scans_list

def download_report(scan_id, scans_list):
    get_asset_report()
    for scan in scans_list:
        if str(scan[1]) == scan_id: 
            scan_name = scan[0]
    print(scan_name,end=" ==> ")
    export_url = "https://cloud.tenable.com/scans/" + str(scan_id) +"/export"
    export_payload = {"format": "csv"}
    export_response = requests.request("POST", export_url, json=export_payload, headers=headers).json()
    file_id = export_response["file"]
    export_status_url = "https://cloud.tenable.com/scans/"+ scan_id + "/export/" + file_id + "/status"
    
    while True:
        export_status_response = requests.request("GET", export_status_url, headers=headers).json()
        if export_status_response["status"] == "ready":
            break
        else:
            print("Exporting...")
            time.sleep(5)
        
    if export_response.get("file") is not None:
        # Downloading a scan report
        print("Downloading", end=' ==> ')
        download_url = "https://cloud.tenable.com/scans/" + str(scan_id) + "/export/" +  export_response["file"] + "/download"
        response = requests.request("GET", download_url, headers=headers)
        file_name = "output.csv"
        open(file_name, 'wb').write(response.content)

        # Formatting and renaming of  a scan report
        print("Foramatting the report")
        read_file = pd.read_csv(file_name)
        xl_data_raw = read_file[read_file["Risk"] != "None"]
        xl_data = xl_data_raw.drop(columns=["CVSS Base Score","CVSS Temporal Score","CVSS Temporal Vector","CVSS Vector","CVSS3 Base Score","CVSS3 Temporal Score","CVSS3 Temporal Vector","CVSS3 Vector","System Type"])
        xl_data.to_excel (r'output.xlsx', sheet_name="Raw", index = None, header=True)

        asset_report = pd.read_excel('workbench_report.xlsx', sheet_name='Raw')
        age_data = pd.DataFrame(asset_report, columns=['Plugin ID', 'Asset UUID', 'Age', 'First Seen', 'Last Seen'])

        inner_join = pd.merge(xl_data, age_data, on = ['Plugin ID', 'Asset UUID'], how = 'left')
        inner_join.to_excel (r'output.xlsx', sheet_name="Raw", index=None)  

        newfil = scan_name + "_" + today.strftime("%d_%b_%Y")+ ".xlsx"
        os.rename('output.xlsx',newfil)
        os.remove("output.csv")
    else:
        print("Export failed")
    return newfil

def download_all_reports(folder_id):
    dir_name = "Scan_reports_" + folder_id + "_" + today.strftime("%d_%b_%Y")
    os.mkdir(dir_name)
    print("The files will be saved to " +str(os.getcwd()))
    os.chdir(dir_name)
    get_asset_report()
    scan_folder_url = "https://cloud.tenable.com/scans"
    querystring = {"folder_id":folder_id}
    scans_response = requests.request("GET", scan_folder_url, headers=headers, params=querystring).json()

    counter = 1
    for scan in scans_response["scans"]:
        # Exporting a scan report
        print(str(counter) + ". " + scan["name"]+" Exporting"  , end=' ==> ')
        scan_id = scan["id"]
        export_url = "https://cloud.tenable.com/scans/" + str(scan_id) +"/export"
        # export_status_url = "https://cloud.tenable.com/scans/scan_id/export/file_id/status"
        export_payload = {"format": "csv"}
        export_response = requests.request("POST", export_url, json=export_payload, headers=headers).json()

        file_id = export_response["file"]
        export_status_url = "https://cloud.tenable.com/scans/"+ str(scan_id) + "/export/" + file_id + "/status"
        
        while True:
            export_status_response = requests.request("GET", export_status_url, headers=headers).json()
            if export_status_response["status"] == "ready":
                break
            else:
                print("Exporting...", end=" ==> ")
                time.sleep(5)     

        counter = counter + 1
        if export_response.get("file") is not None :
            # Downloading a scan report
            print("Downloading", end=' ==> ')
            download_url = "https://cloud.tenable.com/scans/" + str(scan_id) + "/export/" +  export_response["file"] + "/download"
            response = requests.request("GET", download_url, headers=headers)
            file_name = "output.csv"
            open(file_name, 'wb').write(response.content)

            # Formatting and renaming of  a scan report
            print("Foramatting the report")
            read_file = pd.read_csv (file_name)
            xl_data_raw = read_file[read_file["Risk"] != "None"]
            xl_data = xl_data_raw.drop(columns=["CVSS Base Score","CVSS Temporal Score","CVSS Temporal Vector","CVSS Vector","CVSS3 Base Score","CVSS3 Temporal Score","CVSS3 Temporal Vector","CVSS3 Vector","System Type"])
            xl_data.to_excel (r'output.xlsx', sheet_name="Raw", index = None, header=True)

            asset_report = pd.read_excel('workbench_report.xlsx', sheet_name='Raw')
            age_data = pd.DataFrame(asset_report, columns=['Plugin ID', 'Asset UUID', 'Age', 'First Seen', 'Last Seen'])

            inner_join = pd.merge(xl_data, age_data, on = ['Plugin ID', 'Asset UUID'], how = 'left')
            inner_join.to_excel (r'output.xlsx', sheet_name="Raw", index=None)  

            newfil = scan["name"] + "_" + today.strftime("%d_%b_%Y")+ ".xlsx"
            os.rename('output.xlsx',newfil)
            os.remove("output.csv")

        else:
            print("Export failed")
    os.chdir("..")

def download():
        folders()
        folder_ID = input("Enter the folder ID: ")
        scan_list = scans(folder_ID)
        scan_id = input("Enter the scan ID: ")
        if scan_id == "0000":
            download_all_reports(folder_ID)
        elif scan_id != None :
            download_report(scan_id=scan_id, scans_list = scan_list)
        else:
            print("Enter a correct scan ID")

def runScan():
    folders()
    folder_ID = input("Enter the folder ID: ")
    scan_list = scans(folder_ID)
    scan_id = input("Enter the scan ID: ")
    if scan_id == "0000":
        noFeature()
    elif scan_id != None :
        scan_url = "https://cloud.tenable.com/scans/" + scan_id + "/launch"
        scan_response = requests.request("POST", scan_url, headers=headers)
        print("Scan is started.\n", scan_response.text)

def statusCheck():
    folders()
    folder_ID = input("Enter the folder ID: ")
    scan_list = scans(folder_ID)
    scan_id = input("Enter the scan ID: ")
    if scan_id == "0000":
        noFeature()
    elif scan_id != None :
        status_url = "https://cloud.tenable.com/scans/" + scan_id + "/latest-status"
        status_response = requests.request("GET", status_url, headers=headers).json()
        print("Scan is ", status_response["status"])

def scandetails():
    folders()
    folder_ID = input("Enter the folder ID: ")
    scan_list = scans(folder_ID)
    scan_id = input("Enter the scan ID: ")
    
    scan_details_url = "https://cloud.tenable.com/scans/"+scan_id
    scan_details = requests.request("GET", scan_details_url, headers=headers).json()

    epoch_time = scan_details["info"]["scan_end"]
    end_time = datetime.datetime.fromtimestamp( epoch_time ) 

    export_url = "https://cloud.tenable.com/scans/"+scan_id+"/export"
    export_payload = {"format": "csv"}
    export_response = requests.request("POST", export_url, json=export_payload, headers=headers).json()
    file_id = export_response["file"]

    export_status_url = "https://cloud.tenable.com/scans/"+scan_id+"/export/" + file_id + "/status"

    while True:
        export_status_response = requests.request("GET", export_status_url, headers=headers).json()
        if export_status_response["status"] == "ready":
            break
        else:
            print("Exporting...")
            time.sleep(5)
        
    if export_response.get("file") is not None:
        # Downloading a scan report
        download_url = "https://cloud.tenable.com/scans/"+scan_id+"/export/" +  export_response["file"] + "/download"
        response = requests.request("GET", download_url, headers=headers)
        file_name = "output.csv"
        open(file_name, 'wb').write(response.content)

        read_file = pd.read_csv (file_name)
        xl1_data = read_file[read_file["Risk"] != "None"]
        xl_data = xl1_data.drop_duplicates(subset=['Plugin ID', 'Host'])
        vulns = xl_data["Risk"] != "None"
        criticals = xl_data["Risk"] == "Critical"
        highs = xl_data["Risk"] == "High"
        mediums = xl_data["Risk"] == "Medium"
        lows = xl_data["Risk"] == "Low"
        print("================Scan details================")
        print("Scan name =", scan_details["info"]["name"])
        print("Host count =", scan_details["info"]["hostcount"])
        print("Scan end time =", end_time )
        print("Total vulnerabilities = ", vulns.sum())
        print("Critical vulnerabilities = ", criticals.sum())
        print("High vulnerabilities =",  highs.sum())
        print("Mediums vulnerabilities =", mediums.sum())
        print("Lows vulnerabilities = ", lows.sum())
        os.remove("output.csv")
    else:
        print("Scan is not avilable.")

def scan_Status_check(scan_id):
    status_url = "https://cloud.tenable.com/scans/" + scan_id + "/latest-status"
    status_response = requests.request("GET", status_url, headers=headers).json()
    return status_response["status"]

def send_mail(reportname, receiever):
    report = '"'+reportname+'"'
    # print(reportname)
    cmd = "Send-MailMessage -From " + sender + " -To " + receiever + " -Cc "+ cc +" -Subject " + subject + " -Attachments  ./" + report  + " -Body " + body + " -DeliveryNotificationOption OnFailure -SmtpServer " + smtp
    completed = subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True)
    if completed.returncode == 0:
        return True
    elif completed.returncode == 1:
        return False
 
def sendReport():

    if smtp == None:
        print("Configure SMTP, SENDER and CC details in .env file to use this feature")
        return

    receiever = input("Enter reciepient email-id: ")
    folders()
    folder_ID = input("Enter the folder ID: ")
    scan_list = scans(folder_ID)
    scan_id = input("Enter the scan ID: ")
    if scan_id == "0000":
        noFeature()
    elif scan_id != None :
        while True:
            if scan_Status_check(scan_id) == "completed":
                reportname = download_report(scan_id=scan_id, scans_list = scan_list)
                if send_mail(reportname, receiever):
                    print("Report sent successfully")
                else:
                    print("Report didn't send. Sorry :(")
                break
            elif scan_Status_check(scan_id) == "aborted":
                print("The scan is aborted. Try to re-run the scan.")
                break
            elif scan_Status_check(scan_id) == "canceled":
                print("The scan is canceled. Try to re-run the scan.")
                break
            elif scan_Status_check(scan_id) == "empty":
                print("The scan is not started yet. Start the scan.")
                break
            elif scan_Status_check(scan_id) == "initializing":
                print("Tenable.io is preparing the scan request for processing. Let's wait for 15 minutes. ")
                time.sleep(900)  
            elif scan_Status_check(scan_id) == "pausing":
                print("The scan is getting paused. Resume the scan.")
                break  
            elif scan_Status_check(scan_id) == "paused":
                print("The scan is paused. Resume the scan.")
                break  
            elif scan_Status_check(scan_id) == "pending":
                print("Scan is in pending state. Let's wait for 15 minutes. ")
                time.sleep(900)  
            elif scan_Status_check(scan_id) == "resuming":
                print("Scan is resuming. Let's wait for 15 minutes. ")
                time.sleep(900)  
            elif scan_Status_check(scan_id) == "running":
                print("Scan is running. Let's wait for 15 minutes. ")
                time.sleep(900)  
            elif scan_Status_check(scan_id) == "stopped":
                print("Scan is stopped")
                break  
            elif scan_Status_check(scan_id) == "stopping":
                print("Scan is stopping.")
                break 
            else:
                print("Unknown status, hence closing.")
                break

if __name__ == "__main__":
    
    while True:
        action = input('''Enter your selection: 
1. Download
2. Run a scan
3. Check scan status
4. Scan details
5. Send report
0. Exit\n''')
        if action == "0":
            exit
        elif action == "1":
            download()
        elif action == "2":
            runScan()
        elif action == "3":
            statusCheck()
        elif action == "4":
            scandetails()
        elif action == "5": 
            sendReport()
        else:
            print("Enter a correct value")

        exit_switch = input("To exit enter 'q', to continue hit enter: ")
        if exit_switch == "q" or exit_switch == "Q":
            break