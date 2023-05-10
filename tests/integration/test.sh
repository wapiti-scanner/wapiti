#!/bin/bash

function all() {
  local arr=("$@")
  for element in "${arr[@]}"; do
    if [[ "$element" -eq 0 ]]; then
      return 1
    fi
  done
  return 0
}
wapiti --help

modules=(
    "backup" 
    "brute_login_form" 
    "buster" 
    "cookieflags" 
    "crlf" 
    "csp" 
    "csrf" 
    "drupal_enum" 
    "exec" 
    "file" 
    "htaccess"
    "htp"
    "http_header" 
    "log4shell" 
    "methods" 
    "nikto"
    "permanentxss"
    "redirect" 
    "shellshock" 
    "sql" 
    "ssl" 
    "ssrf" 
    "takeover"
    "timesql" 
    "wapp" 
    "wp_enum" 
    "xss"
    "xxe"
)

tested_modules=(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)

while ! all $tested_modules; do 
    for i in "${!modules[@]}"; do
        if [[ "${tested_modules[$i]}" -eq 0 ]]; then
            curl http://"${modules[$i]}" > /dev/null
            if [[ $? -eq 0 ]]; then
              tested_modules[$i]="1"
              echo "testing module ${modules[$i]}"
              wapiti -u http://"${modules[$i]}" -m "${modules[$i]}" -f json -o /home/"${modules[$i]}".out --flush-session
            else
              echo "container for module ${modules[$i]} not available yet"
            fi
        fi 
    done
done