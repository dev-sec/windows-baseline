# encoding: utf-8

title 'Windows Script Host (WSH)'

control 'wsh-101' do
  impact 1.0
  title 'Windows Script Host mitigations'
  ref url: 'https://labsblog.f-secure.com/2016/04/19/how-to-disable-windows-script-host/'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings') do
    it { should exist }
    its('Enabled') { should eq 0 }
    its('IgnoreUserSettings') { should eq 1 }
  end
end
