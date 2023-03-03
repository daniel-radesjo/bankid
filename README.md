# bankid
Extract BankID information from mobile forensic full file extractions

# Required applications
- binwalk v2.2.1
- 7z 16.02
- plistutil 2.2.0
- xxd V1.10
- base64 (cGNU oreutils) 8.32
- dd (coreutils) 8.32

Install required applications on Debian
```
apt install binwalk p7zip libplist-utils xxd coreutils
```

# Information
- Support for reading compressed zip/ufdr and stand-alone ngp file.<br/>
- UUID (iOS) is read from keychain.plist in same directory as zip/ufdr/ngp.<br/>
- android_id (Android) is read from settings_ssaid.xml in zip/ufdr or xml in same directory as ngp.<br/>
- add "-debug" as last parameter to enable debugging

# Extract information
```
./bankid.sh <zip|ufdr|ngp> [-debug]
```

# Examples
```
./bankid.sh files_full.zip
./bankid.sh 0.ngp
./bankid.sh 0.ngp -debug
```
