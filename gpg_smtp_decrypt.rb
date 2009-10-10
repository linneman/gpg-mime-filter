=begin
  GPG decryption script
  
  Requires a running GPGServer and uses another (proprietary protocol 
  addon to ESMPT for declaring source and target file for decryption. 
  This allows to reuse passphrase and GPG/MIME implementation which is 
  already implemented for the GPGServer
  
  (C) 2009, GNU General Public Licence, Author: Otto Linnemann
=end

# ------------- Main script  ------------- 
# Invocation: ruby gpg_smtp_decrypt encrypted_source_file decrypted_target_file [configfile]


# Read configuration file 

require 'socket'
require 'plist_parser'

LINESEP = "\r\n"
result = 0

if ARGV[3] == nil
  # in case no config file is given use default (here for MacOS X)
  configfilename = File.join( ENV["HOME"], "/Library/Preferences/GpgServer.plist" )
else
  configfilename = ARGV[3]
end


xml = ""
File.open( configfilename, "r") { |stream| xml = stream.read}
config  = PropertyParser.new.parse( xml )

extSmtp=config[0]["External SMTP"]
local=config[0]["Local SMTP"]
server_port = local["Port"]


begin
  # connect to server
  s = TCPSocket.open( "localhost", server_port )
rescue 
  STDERR.puts "GPGServer not running or couldn't connect!"
  exit -1
end


begin
  # reads server greeting message
  msg = s.gets 
  puts msg
  raise "Connection error" if !msg.match("GPG SMTP")
  
  # writes decode command to server 
  s.write "gpgdecode" + LINESEP

  # read ack from server
  msg = s.gets 
  puts msg

  # write source and target file to server
  s.write '"'+ARGV[0] +'" "' + ARGV[1] + '"' + LINESEP

  # read status from server
  msg = s.gets
  puts msg
  raise "GPG error: " + msg if !msg.match("250 Decryption: OK")

rescue => exception
  STDERR.puts "Decode error occured: "+exception.to_s
  result = -1
  
ensure
  # write quit to server
  s.write "QUIT" + LINESEP
  s.close
  exit result
  
end
__END__
