# encoding: utf-8

title 'Mimikatz mitigations'

control 'mimikatz-101' do
  impact 1.0
  title 'Mimikatz mitigations'
  describe registry_key('HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest') do
    it { should exist }
    its('UseLogonCredential') { should eq 0 }
  end
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('FilterAdministratorToken') { should eq 1 }
    its('LocalAccountTokenFilterPolicy') { should eq 0 }
  end
end

