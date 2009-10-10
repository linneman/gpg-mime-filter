=begin
  GPG/MIME Encoder and Decoder.
  
  Classes for the encryption and decryption of email according to RFC3156.

  (C) 2009, General Public Licence, Author: Otto Linnemann
=end

require 'digest/sha1'
require 'open3'

class MimeParser
    
  LINESEP = "\r\n"
  
  def initialize
    @header_str = ""
    @content_str = ""
    @log = nil
  end
  
  def log( string )
    if @log
      @log.puts string
      @log.flush
    end
  end

  # output data stream for logging
  def setLogStream( stream )
    @log = stream
  end

  # reads complete mime chunk from specified stream
  def read_next_message( stream )
    
    # stripe initial empty lines
    while( ( line = stream.gets() ) != nil )
      break if( line.chomp.length != 0 ) 
    end
    
    # read message header
    @header_str << line;
    while( ( line = stream.gets() ) != nil )
       @header_str << line;
      break if( line.chomp.length == 0 )
    end
        
    # read message content
    while( ( line = stream.gets() ) != nil )
       @content_str << line;
      break if( line == "." )
    end
        
    # make sure the message carries original CRLF style
    @header_str.gsub!( LINESEP, "\n" )
    @header_str.gsub!( "\n", LINESEP )
    @content_str.gsub!( LINESEP, "\n" )
    @content_str.gsub!( "\n", LINESEP )

  end
  
  
  def getHeader
    @header_str
  end
  
  
  def getContent
    @content_str
  end
  
  def getMessage
    getHeader + getContent
  end
  
  
private
  
  # get the range for the complete key-value pair, required to remove key
  def getKeyStringRange( key, string, sepchar )
    keystring = key+sepchar
    if string.match(/^#{keystring}/) == nil
      return
    end
    start_index = string.index(/^#{keystring}/)
    cont_str = string[start_index, string.length - start_index] 
    line_length = cont_str.index(/\r\n[-a-zA-Z0-9_"]/) + 2 # CRLF has to be removed too
    [start_index, line_length]
  end
  
  
  # generates array with start index and the length for the value of the given key value
  # for the given string and key separation character (: or =)
  def getKeyValueRange( key, string, sepchar )

    keystring = key+sepchar
    
    start_index = string.index(/^#{keystring}/) 
    if( start_index != nil )
      
      start_index += keystring.length
      cont_str = string[start_index, string.length - start_index]
      value_length = cont_str.index(/\r\n[-a-zA-Z0-9_"]/)
      if( value_length == nil )
        value_length = cont_str.length
        if cont_str[cont_str.length-2,2] == LINESEP
          value_length -= 2   # keep CRLF
        end
      end
 
      if value_length > 0
        [start_index, value_length]
      else
        nil
      end
      
    else
      nil
    end
  end  
  
  
public  
  
  # retrieves value for given key
  def getValueForKey( key, string = @header_str )
    value_range = getKeyValueRange( key, string, ":" )
    if value_range != nil 
      string[ *value_range ].chomp
    else
      ""
    end
  end
  
  
  # assigns a value to a given key
  def setValueForKey( key, value, string = @header_str )
    value_range = getKeyValueRange( key, string, ":" )
    if value_range != nil
      string[ *value_range ] = " "+value
    else
      string.sub!( LINESEP+LINESEP,  LINESEP + key+": "+value + LINESEP+LINESEP )
    end
  end
 
 
  # remove a specific key
  def removeKey( key, string = @header_str )
    value_range = getKeyStringRange( key, string, ":" )
    string[ *value_range ] = "" if value_range != nil
  end
  
  
  # retrieves value for given subkey, find corresponding 
  # main key with getValueforKey value first 
  def getValueForSubKey( key, string )
    keystring = key+"="    
    /(#{keystring})(.+)(;|#{LINESEP})/m =~ ( string+";" )
    if Regexp.last_match(2) != nil 
      Regexp.last_match(2).chomp
    else
      ""
    end
  end
  
  
  # assigns a value to a given sub key, similar to getValueForSubKey
  def setValueForSubKey( key, value, string )
    keystring = key+"="
     /(#{keystring})(.+)(;|#{LINESEP})/m =~ ( string+";" )
    offset = Regexp.last_match.offset(2) 
    value_range = [offset[0], offset[1]-offset[0]]
    
    if value_range != nil
      string[ *value_range ] = value
    else
      string << "; "+key+"=\""+value+"\""
    end
  end  
  
  
  # retrieves value for Content-Transfer-Encoding
  def getContentTransferEncoding()
    getValueForKey("Content-Transfer-Encoding")
  end
  
  
  # sets value for Content-Transfer-Encoding
  def setContentTransferEncoding( value )
    setValueForKey( "Content-Transfer-Encoding", value )
  end
  
  
  # retrieves value for Content-Type
  def getContentType()
    getValueForKey("Content-Type")
  end
  
  
  # sets value for Content-Type
  def setContentType( value )
    setValueForKey( "Content-Type", value )
  end


  # get sender (from)
  def getSender()
    getValueForKey("From")
  end

  
  # get to recipient
  def getToRecipients()
    getValueForKey("To")
  end


  # get CC recipient
  def getCCRecipients()
    getValueForKey("Cc")
  end
  
  
  # get BCC recipient
  def getBCCRecipients()
    getValueForKey("Bcc")
  end
  
  
  # get all recipients()
  def getAllRecipients()
    getToRecipients + getCCRecipients + getBCCRecipients
  end
  
  
  # get all recipients as array of strings
  def getAllRecipientsAsArray()
    str = getAllRecipients
    list = []
    
    while ( /[\.A-Za-z_-]+@[\.A-Za-z_-]+/ =~ str ) != nil
      range = Regexp.last_match.offset(0)
      len = range[1]-range[0]
      list << str[range[0], len]
      str[range[0]-1, len+1] = ""
    end
    
    list
  end
  
  
end



class GpgMime < MimeParser
  
  # find gpg command path
  def initialize
    super
    path_array = ["/usr/bin/", "/usr/local/bin/", "/opt/bin/", "/opt/local/bin/"] 
    path_array.each do |e|
      fullname = e+"gpg"
      if File.exist?(fullname)
        @gpgCmd = fullname
        break
      end
    end
  end
  
  
  private

  TMPDIR          = "/tmp"
  @gpgCmd         = "gpg"
  GPG_STDOUT_FILE = "gpgstdout"
  GPG_STDIN_FILE  = "gpgstdin"
  GPG_STDERR_FILE = "gpgstderr"
  
  
  # retrieves attachment based on type, sufficient for the given PGP/Mime
  # application where we do have only two attachemts which can be distinguished 
  # in this way
  def getSubContentOfType( type, boundary )
    if( ( /(Content-Type:)(.*?)(#{type})/ =~ @content_str ) == nil )
      return nil 
    end
    
    att_beg = Regexp.last_match.offset(0)[1]
    att_end = att_beg + @content_str[ att_beg, @content_str.length - att_beg ].match( boundary ).offset(0)[0]
        
    att_str = @content_str[ att_beg, att_end - att_beg]
        
    cont_beg_index = att_str.match(LINESEP+LINESEP).offset(0)[1]
    att_str[ cont_beg_index, att_str.length - cont_beg_index]
  end
 
  
  # adds signature information of string to the bottom of 
  # a MIME message
  def add_signature( string )
    is_html = false
       
    # check mime type and get boundary 
    cntType = getContentType()
    if cntType == nil
      return "no content type error!"
    end

    # depending on format we patch html or insert plain text     
    if cntType.downcase.match("multipart/alternative") or cntType.downcase.match("text/html")
        string.gsub!("ä", "&auml;" )
        string.gsub!("ö", "&ouml;" )
        string.gsub!("ü", "&uuml;" )
        string.gsub!("Ä", "&Auml;")
        string.gsub!("Ö", "&Ouml;")
        string.gsub!("Ü", "&Uuml;")
        string.gsub!("ß", "&szlig;" )
        
        @content_str.sub!("</body>", "<hr/>" + string.gsub("\n", "<br>\n") + "<hr/></body>")        
    else
        string.gsub!("ä", "ae" )
        string.gsub!("ö", "oe" )
        string.gsub!("ü", "ue" )
        string.gsub!("Ä", "Ae")
        string.gsub!("Ö", "Oe")
        string.gsub!("Ü", "Ue")
        string.gsub!("ß", "ss" )
        
        @content_str << LINESEP + 
        "________________________________________________________________________________\n" +
        string   
    end

  end
  
  
  # invokes gpg with optionstring and passphrase if required
  # we use file I/O as workaround for ruby broken stream error 
  # when writing larger amounts of data to process pipes
  def gpg( recipient_array, inputstr, optionstr, passphrase=nil )
    
    outputstr = ""
    messagestr = ""

    # generate message options for gpg
    recipient_str = ""
    recipient_array.each { |address| recipient_str << "-r "+address+" " }        
  
    # open pipe for passphrase
    pp_read, pp_write = IO.pipe 
    if passphrase != nil
      pp_write.puts( passphrase )
      pp_option = "--passphrase-fd #{pp_read.fileno}"      
    else
      pp_option = " "
    end
    
    command = @gpgCmd + " " + optionstr  + " " + pp_option + " " + recipient_str 
    log "GPG-Command: " + command  
    Open3.popen3(command) do |stdin, stdout, stderr|
      Thread.new {
        stdin.write( inputstr )
        stdin.close_write
      }
      
      outputstr = stdout.read
      messagestr = stderr.read
    end

    pp_write.close
    pp_read.close

    # result code currently not supported by popen3
    gpg_result_code = 0
    
    # result array
    [outputstr, messagestr, gpg_result_code]
  end
  
  
  
  public
  
  
  # checks whether given passphrase is correct
  def check_passphrase( passphrase )
    signature, gpgmsg, gpg_result_code = 
      gpg( [], "to_sign", "--batch -o - -abs", passphrase )
    
    # process signature
    if( gpgmsg.length == 0 )
      true
    else
      false
    end
    
  end
  
  
  # encrypts and signs class internals or delivers error message in case of errors
  # if passphrase is provided, the message is signed with the default key
  def encrypt_and_sign( passphrase, recipient_array = nil )
    gpgmsg = ""    
    boundary = "--" + Digest::SHA1.hexdigest( getHeader )
    
    # construct message content to encrypt
    to_encrypt = "Content-Type: "+ getContentType + LINESEP + 
      "Content-Transfer-Encoding: " + getContentTransferEncoding + LINESEP + LINESEP + 
      @content_str

    # if recipient array is not given, use all recipients
    # which are specified within MIME-header
    if( recipient_array == nil )
      recipient_array = getAllRecipientsAsArray()
    end

    # invoke gpg subprocess
    optionstr = "--batch -ea"
    optionstr += "s" if passphrase != nil
    encrypted, gpgmsg, gpg_result_code = 
      gpg( recipient_array, to_encrypt, optionstr, passphrase )
        
    # handle encrypted result
    if( gpgmsg.length == 0 )
      # Success, store encryption result to class internals 
      
      @content_str = 
        "This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)"+LINESEP+
        "--#{boundary}"+LINESEP+
        "Content-Type: application/pgp-encrypted"+LINESEP+
        "Content-Description: PGP/MIME version identification"+LINESEP+
        LINESEP+
        "Version: 1"+LINESEP+
        LINESEP+
        "--#{boundary}"+LINESEP+
        "Content-Type: application/octet-stream; name=\"encrypted.asc\""+LINESEP+
        "Content-Description: OpenPGP encrypted message"+LINESEP+
        "Content-Disposition: inline; filename=\"encrypted.asc\"" +LINESEP+
        LINESEP+
        encrypted + LINESEP+
        "--#{boundary}--" + LINESEP

      setContentType( "multipart/encrypted;" + LINESEP + 
         "\tprotocol=\"application/pgp-encrypted\";" + LINESEP + 
         "\tboundary=\""+boundary+"\"")
         
    end
    
    # deliver gpg error code to invoker if any
    gpgmsg
    
  end
  
  
  # encrypts class internals or delivers error message in case of errors
  # if passphrase is provided, the message is signed with the default key  
  def encrypt
    encrypt_and_sign( nil )
  end
  
  
  # generates clear text signature for class internals or delivers error message 
  # in case of errors
  def clearsign( passphrase )
    gpgmsg = ""
    signature = ""
    
    boundary = "--" + Digest::SHA1.hexdigest( getHeader )
    
    # determine which part of the message to be signed
    to_sign = "Content-Type: "+ getContentType + LINESEP
    if getContentTransferEncoding.length > 0
      to_sign << "Content-Transfer-Encoding: " + getContentTransferEncoding + LINESEP + LINESEP
    end
    to_sign << @content_str
    

    # make sure everything is encoded DOS like (CR+LF)
    to_sign.gsub!( /\r\n/, "\n" ) # in case we have already DOS encodings we code back
    
    # remove initial and trailing blanks
    to_sign.gsub!(/^[ ]+/,"")
    to_sign.gsub!(/[ ]+$/,"")
    
    # signed content must end with a CR+LF sequence, so make sure  
    # that there is only one CR first
    i = to_sign.length - 1
    while( to_sign[i] == ?\n && i > 0 ) do i-=1; end
    to_sign = to_sign[0, i+1] + "\n"
        
    # and replace all CR's with CR+LF
    to_sign.gsub!( /\n/, "\r\n" ) # and forth
  
    
    # log file for debugging
=begin
    fp = File.new("to_sign.eml", "w")
    fp.write(to_sign)
    fp.close
=end

    # invoke gpg subprocess
    signature, gpgmsg, gpg_result_code = 
      gpg( [], to_sign, "--batch -o - -abs", passphrase )
    
    # process signature
    if( gpgmsg.length == 0 )
      # Success, store encryption result to class internals 
      
      @content_str = 
        "This is an OpenPGP/MIME signed message (RFC 2440 and 3156)"+LINESEP+
        "--#{boundary}"+LINESEP+
        to_sign

      setContentType( "multipart/signed;" + LINESEP + 
         "\tprotocol=\"application/pgp-signature\"; micalg=pgp-sha1;" + LINESEP + 
         "\tboundary=\""+boundary+"\"")
         
      @content_str << LINESEP + "--#{boundary}" + LINESEP +
        "Content-Type: application/pgp-signature; name=\"signature.asc\"" + LINESEP + 
        "Content-Description: OpenPGP digital signature" + LINESEP + 
        "Content-Disposition: attachment; filename=\"signature.asc\"" + LINESEP + 
        LINESEP + 
        signature + LINESEP + 
        "--#{boundary}--"  + LINESEP + LINESEP
    end
    
    # deliver error messages
    gpgmsg
  
  end
  
  
  private
  
  # decryptes GPG/inline content
  def decrypt( passphrase )
    
    decrypted = ""
    gpgmsg = ""
    
    # check mime type and get boundary 
    cntType = getContentType()
    if cntType.match("application\/pgp-encrypted") == nil
      return "input stream with wrong content-type, must be pgp-encrypted!"
    end
    boundary = getValueForSubKey( "boundary", cntType )
    /(")(.*?)(")/=~boundary
    boundary = "--"+Regexp.last_match(2)
    
    # check PGP/Mime Version ( normally this is in the first attachment )
    version_str = getSubContentOfType( "application\/pgp-encrypted", boundary )    
    if version_str==nil || version_str.match("Version: 1") == nil
      return "only version 1 for application/pgp-encrypted mime type supported!"
    end    
    
    # extract content
    pgp_str = getSubContentOfType( "application\/octet-stream", boundary )  
    if( pgp_str == nil )
      return "missing section application/octed stream in input stream!" 
    end

    # decode message
    # invoke gpg subprocess
    decrypted, gpgmsg, gpg_result_code = 
      gpg( [], pgp_str, "--batch -d ", passphrase )

    # RFC 822 requires originally CRLF, but some mua handle it different
    # split encrypted content in original header and content information
    splitmatch = decrypted.match( LINESEP+LINESEP )
    splitmatch = decrypted.match( "\n\n" ) if splitmatch == nil
    if splitmatch == nil
      return "decrypted content could not be decoded or has no header!"
    end
    
    decrypted_header_end  = splitmatch.offset(0)[0]
    decrypted_content_beg = splitmatch.offset(0)[1]
    decrypted_header = decrypted[0, decrypted_header_end ]
    decrypted_content = decrypted[decrypted_content_beg, decrypted.length - decrypted_content_beg]  
    
    # assign original encoding to header
    setContentType( getValueForKey( "Content-Type", decrypted_header ) )
    setContentTransferEncoding( getValueForKey( "Content-Transfer-Encoding", decrypted_header ) )
        
    # exchange content and attach gpg signature info at the end of the message 
    @content_str = decrypted_content + LINESEP
    add_signature( gpgmsg )
    
    # no decryption error occured so we deliver an empty string
    ""  
  end
  
  
  # checks clear text signature
  def check_clearsig
    # check mime type and get boundary 
    cntType = getContentType()
    if cntType.match("application\/pgp-signature") == nil
      return "input stream with wrong content-type, must be pgp-signature!"
    end
    boundary = getValueForSubKey( "boundary", cntType )
    /(")(.*?)(")/=~boundary
    boundary = "--"+Regexp.last_match(2)
                    
    # extract signed content which must be the first section
    if @content_str.match( boundary+LINESEP ) == nil      
      return "input stream does not provide specified boundaries!"
    end
    
    signed_content = @content_str[Regexp.last_match.offset(0)[1], @content_str.length]
        
    if signed_content.match( LINESEP+boundary ) == nil
      return "input stream does not provide specified boundaries!"
    end
    
    signed_content = $`
    
    # extract key
    sig_str = getSubContentOfType( "application\/pgp-signature", boundary )  
    if( sig_str == nil )
      return "missing section application/pgp-signature in input stream!" 
    end
    
    # and write it to temporary file
    sigfilename = File.join(TMPDIR, "tmp.sig")
    File.open(sigfilename, "w") { |sigstream| sigstream.write sig_str }
    
    # check message signature
    # invoke gpg subprocess
    dummy, gpgmsg, gpg_result_code = 
      gpg( [], signed_content, "--batch --verify #{sigfilename} -", nil )
        
        
    # RFC 822 requires originally CRLF, but some mua handle it different
    # split encrypted content in original header and content information
    splitmatch = signed_content.match( LINESEP+LINESEP )
    splitmatch = signed_content.match( "\n\n" ) if splitmatch == nil
    if splitmatch == nil
      return "signed content has no encoding header!"
    end

    header_end  = splitmatch.offset(0)[0]
    content_beg = splitmatch.offset(0)[1]
    header  = signed_content[0, header_end ]
    content = signed_content[content_beg, signed_content.length - content_beg]    
            
    # assign original encoding to header
    setContentType( getValueForKey( "Content-Type", header ) )
    orig_encoding = getValueForKey( "Content-Transfer-Encoding", header )
    setContentTransferEncoding( orig_encoding ) if orig_encoding.length > 0
    
    # exchange content and attach gpg signature info at the end of the message 
    @content_str = content   
    add_signature( gpgmsg )

    # no decryption error occured so we deliver an empty string
    ""  
  end
  
  public
  
  # invokes depending of content type decrypt or check_clearsig
  def decode( passphrase )
    
    contentType = getContentType()
    res = ""
    
    case      
      when contentType.match( "application\/pgp-signature" )
        res = check_clearsig
      
      when contentType.match( "application/pgp-encrypted" )
        res = decrypt( passphrase ) 
    end
    
    return res
    
  end
  
  # delivers an array with all email addresses to public keys
  def getPubKeyAddressList
    outputstr, messagestr, gpg_result_code = gpg( [], [], "--batch -k " )
    
    if messagestr.length == 0
    
      list = []
    
      while ( /[\.A-Za-z_-]+@[\.A-Za-z_-]+/ =~ outputstr ) != nil
        range = Regexp.last_match.offset(0)
        len = range[1]-range[0]
        list << outputstr[range[0], len]
        outputstr[range[0]-1, len+1] = ""
      end
    
      list
    
    else
      []  # error
    end
    
  end
  
end

__END__
