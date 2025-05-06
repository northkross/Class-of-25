#!/bin/bash
touch /tmp/score.json # score json file which will be stuffed in html later

# json manipulation functions
# in the end, json looks like {header:{title:"title", inject:false, timestamp:"..."}, vulns:[{name:"vuln", points:5},null,...]}
_header() {
    local title="$1"
    local injectbool="$2"
    local date=$(date)
    echo -n "{\"header\":{\"title\":\"$title\", \"inject\":$injectbool, \"timestamp\":\"$date\"}, \"vulns\":[" >> /tmp/score.json
}

_append_found() {
    local vuln_name="$1"
    local points="$2"

    echo -n "{\"name\":\"$vuln_name\", \"points\":$points}," >> /tmp/score.json
}

_append_unsolved() {
    echo -n "null," >> /tmp/score.json
}

_terminate(){
    local template_html_file="$1"
    local html_file="$2"

    # reset html file with template
    cat "$template_html_file" > "$html_file" 
    # remove the trailing comma
    sed -i 's/,\([^,]*\)$/ \1/' /tmp/score.json
    # close brackets
    echo "]}" >> /tmp/score.json
    # stuff raw json into html because CORS prevents reading of local files in JS
    sed -i -e "/<!--JSONHERE-->/r /tmp/score.json" -e "/<!--JSONHERE-->/d" "$html_file"

    rm /tmp/score.json
}

# Function to check if text exists in a file
check_text_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    local points="$4"
    
    if grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    local points="$5"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_exists3() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local text3="$4"
    local vuln_name="$5"
    local points="$6"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file" && grep -q "$text3" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_with_threshold() {
  local file="$1"
  local text_prefix="$2"  
  local threshold="$3"    # The maximum or minimum allowed value
  local vuln_name="$4"
  local points="$5"
  local compare="$6"      # "<" or ">"

  grep -oP "^${text_prefix}(\d+)" "$file" | while IFS= read -r match; do
    local value="${match#"$text_prefix"}"

    if [[ "$compare" == "<" ]]; then
      if (( value <= threshold )); then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
      else
        echo "Unsolved Vuln"
        _append_unsolved
      fi
    elif [[ "$compare" == ">" ]]; then
      if (( value >= threshold )); then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
      else
        echo "Unsolved Vuln"
        _append_unsolved
      fi
    else
      echo "Invalid comparison operator: '$compare'"
      return 1
    fi
  done
}

# Function to check if text does not exist in a file
check_text_not_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    local points="$4"
    
    if ! grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_not_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    local file2="$5"
    local points="$6"
    
    if ! grep -q "$text" "$file" && ! grep -q "$text2" "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
# Function to check if a file exists
check_file_exists() {
    local file="$1"
    local vuln_name="$2"
    local points="$3"
    
    if [ -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

# Function to check if a file has been deleted
check_file_deleted() {
    local file="$1"
    local vuln_name="$2"
    local points="$3"
    
    if [ ! -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_deleted2() {
    local file="$1"
    local file2="$2"
    local vuln_name="$3"
    local points="$4"
    
    if ! -e "$file" && ! -e "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_deleted3() {
    local file="$1"
    local file2="$2"
    local file3="$3"
    local vuln_name="$4"
    local points="$5"
    
    if ! -e "$file" && ! -e "$file2" && ! -e "$file3"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_permissions() {
    local file="$1"
    local expected_permissions="$2"
    local vuln_name="$3"
    local points="$4"
    
    
    # Get the actual permissions of the file in numeric form (e.g., 644)
    actual_permissions=$(stat -c "%a" "$file")
    
    if [ "$actual_permissions" == "$expected_permissions" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_file_ownership() { # Thanks Coyne <3
    local file="$1"
    local expected_owner="$2"
    local vuln_name="$3"
    local points="$4"
    
     if getfacl "$file" 2>/dev/null | grep -q "owner: $expected_owner"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_packages() {
    local package="$1"
    local vuln_name="$2"
    local points="$3"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_packages2() {
    local package="$1"
    local package2="$2"
    local vuln_name="$3"
    local points="$4"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_packages3() {
    local package="$1"
    local package2="$2"
    local package3="$3"
    local vuln_name="$4"
    local points="$5"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package3[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

# keep this line at the beginning, input your image metadata here 
# accepts two args: image name, and injects bool (true/false)
_header "Class of 25" "false"

check_text_exists "/home/dallas/Desktop/Forensics1.txt" "iot-city" "Forensics 1 correct" "4"
check_text_exists "/home/dallas/Desktop/Forensics2.txt" "https://tophermitchell.hair" "Forensics 2 correct" "4"
check_text_not_exists "/etc/group" "koco:x:1010:" "Unauthorized user koco removed" "4"
check_text_not_exists "/etc/group" "lt:x:1011:koco," "koco is not part of the LT group" "4"
check_text_not_exists "/etc/group" "root:x:0:lt" "lt should not have root access" "4"
check_text_exists "/etc/ssh/sshd_config" "Port 22" "SSH runs on port 22" "4"
check_text_exists "/etc/ssh/sshd_config" "AddressFamily inet" "SSH connections only use the IPv4 address family" "4"
check_text_exists "/etc/ssh/sshd_config" "PermitRootLogin no" "SSH doesn't permit root login" "4"
check_text_exists2 "/etc/ssh/sshd_config" "PasswordAuthentication no" "PubkeyAuthentication yes" "SSH uses key based authentication" "4"
check_text_exists "/etc/ssh/sshd_config" "AuthorizedKeysCommandUser nobody" "No Authorized Key Command User" "4"
check_text_exists2 "/etc/samba/smb.conf" "obey pam restrictions = yes" "pam password change = yes" "Samba obeys PAM restrictions" "4"
check_text_exists "/etc/samba/smb.conf" "usershare allow guests = yes" "Samba user with usershare privileges cannot create public shares" "4"
check_text_exists "/etc/samba/smb.conf" "unix password sync = yes" "Samba syncs unix pass with samba pass" "4"
check_text_with_threshold "/etc/samba/smb.conf" "max log size = " "500" "Samba syncs unix pass with samba pass" "4" ">"
check_text_exists2 "/etc/apt/apt.conf.d/20auto-upgrades" 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1"' "System set to automatically update" "4"
check_text_exists "/etc/login.defs" "PASS_MAX_DAYS[[:space:]]*90" "Password must be changed after 90 days" "4"
check_text_exists "/etc/login.defs" "LOGIN_RETRIES[[:space:]]*5" "Not oto many login retries" "4"
check_text_exists3 "/etc/pam.d/common-password" "lcredit=-1" "ucredit=-1" "dcredit=-1" "login complexity enabled" "4"
check_text_exists "/etc/pam.d/common-password" "minlen=16" "minimum password length set" "4"
check_text_exists "/etc/gdm3/daemon.conf" "AutomaticLoginEnable = false" "Automatic login off" "4"
check_packages "nmap" "nmap removed" "4"
check_packages "nginx" "nginx removed" "4"
check_packages "hydra" "hydra removed" "4"
check_file_permissions "/etc/shadow" "600" "shadow file permissions fixed" "4"
check_text_not_exists "/var/spool/cron/crontabs/spencer" "* * * * * apt install hydra" "malicious crontab removed" "4"


# keep this line at the end, input the path to score report html here
# accepts two args: path to template html file, and path to actual html file
_terminate "/etc/scoring/report-template.html" "/home/dallas/Desktop/report.html"
