# encoding: utf-8

title 'Windows Certificates store'

control 'certificates-100' do
  impact 1.0
  title 'Verify the content of Windows certificate store'
  ref url: 'https://support.microsoft.com/en-us/help/293781/trusted-root-certificates-that-are-required-by-windows-server-2008-r2,-by-windows-7,-by-windows-server-2008,-by-windows-vista,-by-windows-server-2003,-by-windows-xp,-and-by-windows-2000'
  describe powershell('dir cert:\ -rec') do
    # necessary and trusted root certificates
    its('matcher') { should match '00c1008b3c3c8811d13ef663ecdf40' }
    its('matcher') { should match 'Thawte Timestamping CA' }
    its('matcher') { should match '79ad16a14aa0a5ad4c7358f407132e65' }
    # (few) Known bad certificates
    its('matcher') { should_not match 'Diginotar' }
    its('matcher') { should_not match 'Superfish' }
    # https://sslbl.abuse.ch/
    its('matcher') { should_not match 'a9240e124ab94f16744d54c250f2df461ddc392b' }
  end
end
