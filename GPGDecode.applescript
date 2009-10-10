(*
	Apple Script for decoding GPG/MIME encrypted or signed messages
	
	requires GPGServer to run
	
	(C) 2009, GNU General Public Licence, Author: Otto Linnemann
*)

on open theFileList
	
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
		tell application "Property List Editor"
			activate
			open PathToConfigFile
		end tell
	end try
	
	repeat with i in theFileList
		set source_file to POSIX path of i
		do shell script "ruby -e ' puts File.join( File.dirname(\"" & source_file & "\"), File.basename(\"" & source_file & "\", \".eml\")+\"_dec.eml\")' "
		set target_file to the result
		do shell script "ruby " & "-C " & toolPath & " gpg_smtp_decrypt.rb  \"" & source_file & "\" \"" & target_file & "\""
	end repeat
	
end open