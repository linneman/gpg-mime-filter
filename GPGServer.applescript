(*
	Apple Script for starting, stopping and configuring the GPG-SMTP-Server
	
	The GPG-SMTP-Server is implemented in ruby. This Apple Script starts and
	stops the server enginge and allows to setup basic parameters as GPG 
	passphrase, SMTP account and passphrase, etc.
	
	(C) 2009, GNU General Public Licence, Author: Otto Linnemann
*)

# setup path to script folders 
set resourcesFolder to ((path to me) as string) & "Contents:Resources:"
set toolPath to (POSIX path of resourcesFolder)

# check for existence of config file /Library/Preferences/GpgServer.plist
set UserName to do shell script "whoami"
set PathToConfigFile to "/Users/" & UserName & "/Library/Preferences/GpgServer.plist"
set PathToDefaultConfigFile to toolPath & "GpgServer.plist"

try
	do shell script "/bin/ls " & PathToConfigFile
on error errMsg number errNum
	do shell script "/bin/cp " & PathToDefaultConfigFile & " " & PathToConfigFile
	display dialog "You need to configure the Filter Server first"
	tell application "Property List Editor" to open PathToConfigFile
end try


# Passphrase dialog
set done to false
set Input to display dialog "GPG-SMPT-Server
Please enter your password for your secret key:" with title "GPG-Password" with icon caution default answer "" buttons {"Cancel", "OK"} default button 2 giving up after 295 with hidden answer

set passphrase to text returned of Input as string
try
	do shell script "ruby " & "-C " & toolPath & " gpg_check_passphrase.rb  " & passphrase
on error
	display dialog "Wrong GPG Passphrase"
	set done to true
end try


# Start/Restart Loop
repeat until done = true
	
	do shell script "ruby " & "-C " & toolPath & " gpg_smtp_server.rb  " & passphrase & " " & PathToConfigFile & " > /dev/null 2>&1 & echo $!"
	set pid to the result
	display dialog "GPG-SMTP-Server is running, process ID is " & pid as string buttons {"Restart", "Stop", "Reconfigure"} with icon alias ((path to me) & "Contents:Resources:running.icns" as string)
	
	if button returned of result = "Stop" then
		set done to true
	else if button returned of result = "Reconfigure" then
		tell application "Property List Editor" to open PathToConfigFile
	end if
	
	do shell script "kill " & pid
	
end repeat
