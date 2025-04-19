#!/bin/bash
# Please give around ~5 minutes for the raw to update
# Scorebot for 2025 Ubuntu Ninjago
echo " "
echo " "
echo "NOTE: Please allow up to 5 minutes for scorebot updates & injects."
echo "Scorebot version: v1"
echo "Injects: NO"

check_text_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    
    if grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}
check_text_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}
check_text_exists3() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local text3="$4"
    local vuln_name="$5"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file" && grep -q "$text3" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        count=count+1
    else
        echo "Unsolved Vuln"
    fi
}
# Function to check if text does not exist in a file
check_text_not_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    
    if ! grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}
check_text_not_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    local file2="$5"
    
    if ! grep -q "$text" "$file" && ! grep -q "$text2" "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}
# Function to check if a file exists
check_file_exists() {
    local file="$1"
    local vuln_name="$2"
    
    if [ -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}

# Function to check if a file has been deleted
check_file_deleted() {
    local file="$1"
    local vuln_name="$2"
    
    if [ ! -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'" 
    else
        echo "Unsolved Vuln"
    fi
}
check_file_deleted2() {
    local file="$1"
    local file2="$2"
    local vuln_name="$3"
    
    if ! -e "$file" && ! -e "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'" 
    else
        echo "Unsolved Vuln"
    fi
}
check_file_deleted3() {
    local file="$1"
    local file2="$2"
    local file3="$3"
    local vuln_name="$4"
    
    if ! -e "$file" && ! -e "$file2" && ! -e "$file3"; then
        echo "Vulnerability fixed: '$vuln_name'" 
    else
        echo "Unsolved Vuln"
    fi
}
check_file_permissions() {
    local file="$1"
    local expected_permissions="$2"
    local vuln_name="$3"
    
    # Get the actual permissions of the file in numeric form (e.g., 644)
    actual_permissions=$(stat -c "%a" "$file")
    
    if [ "$actual_permissions" == "$expected_permissions" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}

check_file_ownership() { # Thanks Coyne <3
    local file="$1"
    local expected_owner="$2"
    local vuln_name="$3"
     if getfacl "$file" 2>/dev/null | grep -q "owner: $expected_owner"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}

check_packages() {
    local package="$1"
    local vuln_name="$2"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}
check_packages2() {
    local package="$1"
    local package2="$2"
    local vuln_name="$3"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}

check_packages3() {
    local package="$1"
    local package2="$2"
    local package3="$3"
    local vuln_name="$4"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package3[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
    else
        echo "Unsolved Vuln"
    fi
}


echo " "
echo "Dallas Debian Class of 25"
echo " "

check_text_exists "/etc/ssh/sshd_config" "Port 22" "SSH runs on port 22"
check_text_exists "/etc/ssh/sshd_config" "AddressFamily inet" "SSH connections only use the IPv4 address family"
check_text_exists "/etc/ssh/sshd_config" "PermitRootLogin no" "SSH doesn't permit root login"
check_text_exists2 "/etc/ssh/sshd_config" "PasswordAuthentication no" "PubkeyAuthentication yes" "SSH uses key based authentication"


