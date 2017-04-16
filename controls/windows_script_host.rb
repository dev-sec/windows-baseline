# encoding: utf-8

title 'Windows Script Host (WSH)'

control 'wsh-101' do
  impact 1.0
  title 'Windows Script Host mitigations'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings') do
    it { should exist }
    its('Enabled') { should eq 0 }
    its('IgnoreUserSettings') { should eq 1 }
  end
end

