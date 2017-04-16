# encoding: utf-8

title 'Windows Web Proxy Auto-Discovery Protocol (WPAD)'

control 'wpad-101' do
  impact 1.0
  title 'WPAD mitigations'
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad') do
    it { should exist }
    its('WpadOverride') { should eq 1 }
  end
end

