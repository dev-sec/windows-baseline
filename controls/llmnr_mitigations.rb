# encoding: utf-8

title 'LLMNR/Responder mitigations'

control 'llmnr-101' do
  impact 1.0
  title 'LLMNR mitigations'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows NT\DNSClient') do
    it { should exist }
    its('EnableMulticast') { should eq 0 }
  end
end
