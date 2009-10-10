=begin

encrypt_smtp_server

Invocation: ruby gpg_passphrase [configfile]

Setup a simple SMTP server for filtering message stream for GPG encryption

If public keys for all recipients in the message stream are available, the
message is encrypted. Otherwise a separate signature is generated

(C) 2009, GNU General Public Licence, Author: Otto Linnemann

=end

require 'net/smtp'
require 'socket'
require 'stringio'

require 'plist_parser'
require 'gpgmime'

class SmtpServer

  LINESEP = "\r\n"
  MULTICLIENTS  = true  # if true more than one process is listening to the input port
  
  # Initialization of SMTP Filter GPG/MIME encryption and decryption add on
  # The parameters are normally retrieved from a configuration file and passphrase dialoges
  def initialize( 
    ext_server, 
    ext_port, 
    ext_account, 
    ext_passphrase, 
    from_address, 
    local_port, 
    gpg_passphrase, 
    logfilename = File.join( ENV["HOME"], "/Library/Logs/GpgServer.log" )
    )
    @mailServerName       = ext_server
    @mailServerPort       = ext_port
    @helo                 = 'localhost.localdomain'
    @account              = ext_account
    @from_address         = from_address
    @smtp_passphrase      = ext_passphrase
    @gpg_passphrase       = gpg_passphrase
    @local_port           = local_port
    @log                  = File.new( logfilename, "w" )
  end
  
  attr_accessor :gpg_passphrase, :smtp_passphrase, :from_address, :account, :helo, :mailServerPort, :mailServerName, :local_port
  
  
  private
  
  def log( string )
    if @log
      @log.puts string
      @log.flush
    end
  end
  
  
  # sends mail via specified SMTP server
  def sendmail( rcpArray, message )
    # File.open("mimeparser_out.eml", "w") { |stream| stream.write( message ) }

    Net::SMTP.start( @mailServerName, @mailServerPort, @helo, @account, @smtp_passphrase ) do |smtp|
    	smtp.send_message( message, @from_address, rcpArray )
    end
  end
  
    
  # gpg encryption filter for content
  # returns encrypted_msg, pgpinfo
  def gpgfilter( rcpArray, content_string )
    
    # log "gpgpassphrase "+ @gpg_passphrase
    
    mimeParser = GpgMime.new
    mimeParser.setLogStream( @log )
    
    input_stream = StringIO.open( content_string )
    mimeParser.read_next_message( input_stream )
    pubKeysArray = mimeParser.getPubKeyAddressList
    
    interSec = rcpArray & pubKeysArray
    
    if interSec.length < rcpArray.length
      log "not all in key list"
      gpgmsg = mimeParser.clearsign( @gpg_passphrase ) 
    else
      log "everything in key list, encrypt"
      log "rcpArry-> "
      rcpArray.each { |r| log r }
      gpgmsg = mimeParser.encrypt_and_sign( @gpg_passphrase, rcpArray )
    end
    
    log "gpgmsg: " + gpgmsg if gpgmsg.length > 0
    
    [mimeParser.getMessage, gpgmsg ]
  end


  public

  def handle_client( client )
    
    state = :reg_ack
    clientname = ""
    from_addr = ""
    to_addr = ""
    data = ""
    content = ""
    
 
    line = ""
    rcpArray = []
    
    log "Client is connected, wait for messages"
    client.write "220 localhost GPG SMTP filter"+LINESEP   
       
    begin # rescue exception of this block
         
      loop do

        # State loop

        line = client.gets
      
        if state!=:data_rcv && line.upcase.match(/^QUIT/) then
          log "quit message: " + line
          client.write "221 Bye" + LINESEP
          client.close
          log "Client is disconnected"       
          break 
        end
      
        if state!=:data_rcv && line.upcase.match(/^NOOP/) then next end
        if state!=:data_rcv && line.upcase.match(/^RSET/) then break end
      
        lineprocessed = true
        
        begin  # continue loop
        
          case state
            when :reg_ack
              log ":reg_ack"
              clientname = line
              clientname = clientname.chomp
              log "Connect with client: " + clientname 
              if clientname.upcase.match("GPGDECODE")
                client.write "two arguments expected: gpg_mime_encrypted_file gpg_mime_decrypted_file"+LINESEP
                state = :gpg_decode_ack
              else
                client.write "250 8BITMIME" + LINESEP
                state = :sender_ack
              end
              
            when :gpg_decode_ack
              begin
                if line.match('"')
                  # file arguments are quoted due to spaces
                  line.match(/(["][^"]+["])[ ]+(["][^"]+["])/)
                  filearray = [ Regexp.last_match(1), Regexp.last_match(2) ]
                  filearray.each { |a| a.gsub!('"', '') }
                else
                  # unquoted file arguments
                  filearray = line.split
                end
            
                gpg_encrypted = filearray[0]
                gpg_target = filearray[1]                
              rescue
                raise "error in file specifiers, wrong quotation?"
              end
              
              # do the decryption
              gpgmsg = ""
              begin
                mimeParser = GpgMime.new
                File.open(gpg_encrypted, "r") { |s| mimeParser.read_next_message( s ) }
                gpgmsg = mimeParser.decode( @gpg_passphrase )
                File.open(gpg_target, "w") { |s| s.write( mimeParser.getMessage ) }
              rescue => exception 
                gpgmsg = exception.to_s
              end 
              # if it was ok.
              if gpgmsg.length == 0
                msg = "250 Decryption: OK"
                client.write msg + LINESEP
                log msg + ", EML file " + gpg_encrypted + " and store decoded text to file " + gpg_target
              else
                msg = "600 Decryption Error: " + gpgmsg
                client.write msg + LINESEP
                log msg
              end
              state =:reg_ack
            
            when :sender_ack
              from_addr = line
              log "from address: "+from_addr      
              client.puts "250 Sender OK" + LINESEP
              rcpArray = []
              content = ""
              state = :recipient_ack
    
            when :recipient_ack
              if line.upcase.match( "RCPT TO:" ) 
                /[\.A-Za-z_-]+@[\.A-Za-z_-]+/ =~ line
                rcpArray << $~.to_s
                log "to address: "+ $~.to_s
                client.write "250 Recipient OK" + LINESEP
              else              
                state = :data_ack
                lineprocessed = false
              end
            
            when :data_ack
              log "data message: " + line
              client.write "354 End data with ." + LINESEP
              lineprocessed = true
              state = :data_rcv
    
            when :data_rcv
              if line == "."+LINESEP
                log "end of message received"
          
                encrypted_msg, gpginfo = gpgfilter(rcpArray, content)
          
=begin
                # log files for debugging purposes 
                clear = File.new("clear.eml", "w")
                clear.write( content )
                clear.close
              
                enc = File.new("enc.eml", "w")
                enc.write( encrypted_msg )
                enc.close
=end

                if gpginfo.length == 0
                  sendmail( rcpArray, encrypted_msg )  
                  client.write "250 Ok" + LINESEP
                  log "mail sent, 250 OK signaled, last line received: " + line
                else
                  log "encryption error occured!"
                  client.write "211 " + gpginfo + LINESEP
                end
                state = :sender_ack   # Apple mail does not respectively late send quit, therefore disconnect here
              else 
                content << line
                # log "line: " + line
              end
                
          end # case state 
        
        end until lineprocessed # repeat loop

      end # state loop
    
    rescue => exception
      log "exception occured while sending mail out: " + exception.to_s + ", check your smtp configuration!"
    ensure
      client.close
    end
    
  end #def handle_client( client )


  # starts smtp server
  def run

    server = TCPServer.open( 2000 )
    log "Server is up, waiting for clients ..."
    
    loop {
      if MULTICLIENTS
        Thread.start(server.accept) do |client|
          log "New client is connected"
          handle_client(client)
          # sleep(3)
        end
      else
        # Connection loop 
        client = server.accept
        log "New client is connected"
        handle_client( client )
      end
    }

  end # def run

end # class SmtpServer


# ------------- Main script  ------------- 
# Invocation: ruby gpg_passphrase [configfile]


# Read configuration file 

if ARGV[1] == nil
  # in case no config file is given use default (here for MacOS X)
  configfilename = File.join( ENV["HOME"], "/Library/Preferences/GpgServer.plist" )
else
  configfilename = ARGV[1]
end

xml = ""
File.open( configfilename, "r") { |stream| xml = stream.read}
config  = PropertyParser.new.parse( xml )

extSmtp=config[0]["External SMTP"]
local=config[0]["Local SMTP"]


# Initialize and start up the SMTP GPG/MIME Filter-Server

myServer = SmtpServer.new(
  extSmtp["Server"],
  extSmtp["Port"],
  extSmtp["Account"],
  extSmtp["Passphrase"],
  extSmtp["FromAddress"],
  local["Port"],
  ARGV[0],  # gpg passphrase 
  logfilename = File.join( ENV["HOME"], "/Library/Logs/GpgServer.log" )
  )


# Check Passphrase and run the server

result = 0
if GpgMime.new.check_passphrase( ARGV[0] )
  myServer.run
  result = 0
else
  result = -1
end

exit result


__END__
