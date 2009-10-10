=begin
  GPG passphrase check

  ruby gpg_check_passphrase passphrase
  
  invokes gpg and checks whether given passphrase is correct
=end

require 'gpgmime'
if GpgMime.new.check_passphrase( ARGV[0] )
  result = 0
else
  result = -1
end

exit result

__END__