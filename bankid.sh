#!/bin/bash
# Extract BankID information from mobile forensic full file extractions
# (c) 2023 Daniel Rådesjö

#Return UUID for bankid from keychain.plist (YmlkX2RldmljZWlkX2lk = bid_deviceid_id)
function getUUID() {
  UUID=""
  if ls $(dirname ${1})/*_keychain.plist 1> /dev/null 2>&1; then
    UUID=$(plistutil -f xml -i $(dirname ${1})/*_keychain.plist | grep -A50 YmlkX2RldmljZWlkX2lk | grep -A5 "<key>v_Data</key>" | tr -d "\n" | tr -d "\t" | cut -d">" -f4 | cut -d"<" -f1 | base64 -d)
    if [ -n "${UUID}" ]; then #uuid found
      echo "UUID: ${UUID} ($(basename $(ls $(dirname ${1})/*_keychain.plist)))"
    fi
  fi
}

#Return android_id for bankid from settings_ssaid.xml
function getAndroid_id() {
    
    if [[ $(dd if="${1}" bs=1 count=3 status=none) == "ABX" ]]; then #binary xml
      ANDROID_ID_OFFSET=$(binwalk -R "\x00\x0e\x63\x6f\x6d\x2e\x62\x61\x6e\x6b\x69\x64\x2e\x62\x75\x73" "${1}" 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
      if [ -n "${ANDROID_ID_OFFSET}" ]; then
        ANDROID_ID_OFFSET=$((ANDROID_ID_OFFSET + 21))
        ANDROID_ID=$(dd status=none if="${1}" skip=$((${ANDROID_ID_OFFSET})) bs=1 count=16)
      
        if [ -n "${DEBUG}" ]; then
          printf "android_id offset: 0x%x\n" $((${ANDROID_ID_OFFSET}))
        fi
      fi
      
    else #Not binary xml
      ANDROID_ID=$(grep "com.bankid.bus" ${1} | cut -d"\"" -f6)
    fi
    
    if [ -n "${ANDROID_ID}" ]; then
      echo "android_id: $ANDROID_ID"
    fi
}

#Parse ngp file
function parse() {

  #Issued
  ISSUED_OFFSET=$(binwalk -R "\x23\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00" ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
  ISSUED_OFFSET=$(binwalk -R "\x28" -o $((${ISSUED_OFFSET}+12)) ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
  ISSUED_OFFSET=$((ISSUED_OFFSET + 1))
  ISSUED=$(dd status=none if=${1} skip=$((${ISSUED_OFFSET})) bs=1 count=6)
  
  #Name
  NAME=$(dd status=none if=${1} skip=$((${ISSUED_OFFSET}+14)) bs=1 count=64 | sed "s/ - /#/g" | cut -d"#" -f1)

  #Issuer/Bank
  BANK_OFFSET=$(binwalk -R "\x55\x04\x0a\x0c" ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
  BANK_OFFSET=$((BANK_OFFSET + 4))
  BANK="$(dd status=none if=${1} skip=$((${BANK_OFFSET})) bs=1 count=256 | head -n1 | cut -d")" -f1 | tr -d "'"))"

  #SSN
  SSN_OFFSET=$(binwalk -R "\x55\x04\x05\x13\x0c" ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
  SSN_OFFSET=$((SSN_OFFSET + 5))
  SSN=$(dd status=none if=${1} skip=$((${SSN_OFFSET})) bs=1 count=12)

  #Validity
  VALIDITY_OFFSET=$(binwalk -R "\x5a\x17\x0d" ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)
  VALIDITY_OFFSET=$((VALIDITY_OFFSET + 3))
  VALIDITY=$(dd status=none if=${1} skip=$((${VALIDITY_OFFSET})) bs=1 count=6)

  #Certificates
  CERT="" #List of certs
  CERT_OFFSETS="" #List of certs offsets
  CERTS=$(binwalk -R "\x42\x61\x6e\x6b\x69\x64\x20" ${1} 2>/dev/null | grep 0x | cut -c15- | cut -d" " -f1) #Find "BankID "

  #Loop certificates
  while IFS= read -r CERT_OFFSET;do 
    BANKID_NUMBER=$(dd status=none if=${1} skip=$((${CERT_OFFSET}+7)) bs=1 count=1) #Return x from "Bankid x"
    CERT_OFFSET=$(binwalk -R "\xa0\x03\x02\x01\x02\x02\x08" -o $((${CERT_OFFSET}+7)) -l 64 ${1} 2>/dev/null | grep 0x | head -n1 | cut -c15- | cut -d" " -f1)

    if [ -n "${CERT_OFFSET}" ]; then #Cert found
      CERT_OFFSET=$((CERT_OFFSET + 7))
      CERT="${CERT} $(dd status=none if=${1} skip=$((${CERT_OFFSET})) bs=1 count=8 | xxd -p) (${BANKID_NUMBER})" #Add cert to list of certs
      CERT_OFFSETS="${CERT_OFFSETS} ${CERT_OFFSET}"
    fi
  done <<< "${CERTS}"

  #Debug
  if [ -n "${DEBUG}" ]; then 
    echo "NGP: ${1}"
    echo "TMP: ${TMP}"
  fi
  
  echo "Name: $NAME"
  echo "SSN: ${SSN:0:8}-${SSN:8:4}"
  echo "Issuer: $BANK"
  echo "Certificates:$CERT"
  echo "Issued: 20${ISSUED:0:2}-${ISSUED:2:2}-${ISSUED:4:2}"
  echo "Validity: 20${VALIDITY:0:2}-${VALIDITY:2:2}-${VALIDITY:4:2}"
 
  #Debug
  if [ -n "${DEBUG}" ]; then
    printf "Issuer offset: 0x%x\n" $((${BANK_OFFSET}))
    
    printf "Certificates offset:"
    while IFS= read -r CERT_OFFSET; do
      printf " 0x%x" ${CERT_OFFSET}
    done <<< "${CERT_OFFSETS}"
    printf "\n"
    
    printf "SSN offset: 0x%x\n" $((${SSN_OFFSET}))
    printf "Issued offset: 0x%x\n" $((${ISSUED_OFFSET}))
    printf "Validity offset: 0x%x\n" $((${VALIDITY_OFFSET}))
  fi 

}

#Enable debug mode if "-debug" is used
if [ "${2}" == "-debug" ]; then DEBUG=1; fi

#Check for installed applications
APPS=( binwalk dd 7z plistutil base64 xxd )
for i in "${APPS[@]}"; do
  if ! command -v "${i}" &> /dev/null; then
    echo "${i} is missing"; exit 1
  fi
done

#Precheck for input parameters and file exist
if [ -z "${1}" ]; then echo "Usage: ${0} <zip/ufdr/ngp>"; exit 1; fi
if ! ls "${1}" 1> /dev/null 2>&1; then echo "${1} doesn't exists"; exit 1; fi

if [ -n "${DEBUG}" ]; then echo "Reading file: ${1}"; fi

#Input file type handler (zip/ngp)
if [[ "${1}" == *.zip || "${1}" == *.ufdr ]]; then #zip/ufdr
  
  NGP=$(7z l "${1}" 2>/dev/null | egrep ngp$ | cut -c54-) #Find ngp files in zip
  
  if [ ! -z "${NGP}" ]; then #ngp found
    #Get multiple ngp files
    NGPS=$(echo "${NGP}" | rev | cut -d"/" -f1 | rev | tr "\n" " " | sed "s/ *$//g")
    
    #Loop ngp files
    while IFS= read -r line;do
    
      NGP=$(echo "${line}" | rev | cut -d"/" -f1 | rev | tr -d "\n")
    
      #Decompress ngp from zip
      TMP="$(mktemp /dev/shm/bankid.XXXXXXXX)" || exit 4
      7z e -so "${1}" "${line}" 2>/dev/null > ${TMP}

      echo "File: ${1} ($NGP / $NGPS)" #Print file information
      parse "${TMP}"
      if [ -z "${DEBUG}" ]; then rm ${TMP}; fi #Don't delete ngp file if debug is enabled
      getUUID "${1}" #Get UUID from *_keychain.plist
      
      #Get android_id from settings_ssaid.xml
      SETTINGS_SSAID=$(7z l "${1}" 2>/dev/null | egrep settings_ssaid.xml$ | cut -c54-) #Find settings files in zip
      if [ -n "${SETTINGS_SSAID}" ]; then #Exit if no settings file found
        TMP="$(mktemp /dev/shm/settings_ssaid.XXXXXXXX)" || exit 4
        7z e -so "${1}" "${SETTINGS_SSAID}" 2>/dev/null > ${TMP}

        if [ -n "${DEBUG}" ]; then echo "android_id TMP: ${TMP}"; fi

        getAndroid_id ${TMP}
        
        if [ -z "${DEBUG}" ]; then rm ${TMP}; fi #Don't delete temp file if debug is enabled
      fi
  
      printf '%.0s-' {1..80}; echo ""
      
    done <<< "${NGP}"
    
  else
    getUUID "${1}" #Get UUID from *_keychain.plist
    
    #Get android_id from settings_ssaid.xml
    SETTINGS_SSAID=$(7z l "${1}" 2>/dev/null | egrep settings_ssaid.xml$ | cut -c54-) #Find settings files in zip
    
    if [ -n "${SETTINGS_SSAID}" ]; then #Exit if no settings file found
      TMP="$(mktemp /dev/shm/settings_ssaid.XXXXXXXX)" || exit 4
      7z e -so "${1}" "${SETTINGS_SSAID}" 2>/dev/null > ${TMP}

      if [ -n "${DEBUG}" ]; then echo "android_id TMP: ${TMP}"; fi
      getAndroid_id "${TMP}"
      if [ -z "${DEBUG}" ]; then rm ${TMP}; fi #Don't delete temp file if debug is enabled
    fi
  fi
  
else #Not zip or ufdr (ngp)
  echo "File: ${1}" #Print file information
  parse "${1}"  
  getUUID "${1}" #Get UUID from *_keychain.plist
  
  #Get android_id from settings_ssaid.xml
  if ls $(dirname "${1}")/settings_ssaid.xml 1>/dev/null 2>&1; then
    getAndroid_id "$(dirname "${1}")/settings_ssaid.xml"
  fi
fi
