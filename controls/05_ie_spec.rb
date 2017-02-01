# encoding: utf-8

title 'Windows IE Configuration'

control 'windows-ie-101' do
  impact 1.0
  title 'IE 64-bit tab'
  describe registry_key('HKLM\Software\Policies\Microsoft\Internet Explorer\Main') do
    it { should exist }
    its('Isolation64Bit') { should eq 1 }
  end
end

control 'windows-ie-102' do
  impact 1.0
  title 'Run antimalware programs against ActiveX controls'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3') do
    it { should exist }
    its('270C') { should eq 0 }
  end
end
