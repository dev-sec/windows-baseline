# encoding: utf-8

title 'LLMNR/Responder mitigations'

control 'llmnr-101' do
  impact 1.0
  title 'LLMNR mitigations'
  ref url: 'http://windowsitpro.com/networking/q-how-can-i-disable-netbios-over-tcpip-windows-server-core-installations'
  ref url: 'https://technet.microsoft.com/en-us/library/cc775874%28v=ws.10%29.aspx'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows NT\DNSClient') do
    it { should exist }
    its('EnableMulticast') { should eq 0 }
  end
end
