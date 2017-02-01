# encoding: utf-8

title 'Windows Audit & Logging Configuration'

control 'windows-audit-100' do
  impact 0.1
  title 'Configure System Event Log (Application)'
  desc 'Only appies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Application') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
end

control 'windows-audit-101' do
  impact 0.1
  title 'Configure System Event Log (Security)'
  desc 'Only appies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Security') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
end

control 'windows-audit-102' do
  impact 0.1
  title 'Configure System Event Log (Setup)'
  desc 'Only appies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
end

control 'windows-audit-103' do
  impact 0.1
  title 'Configure System Event Log (System)'
  desc 'Only appies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\System') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
end

control 'windows-audit-201' do
  impact 1.0
  title 'Kerberos Authentication Service Audit Log'
  desc '
    policy_name: Audit Kerberos Authentication Service
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon
  '
  describe audit_policy do
    its('Kerberos Authentication Service') { should_not eq 'No Auditing' }
  end
end

control 'windows-audit-202' do
  impact 1.0
  title 'Kerberos Service Ticket Operations Audit Log'
  desc '
    policy_name: Audit Kerberos Service Ticket Operations
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon
  '
  describe audit_policy do
    its('Kerberos Service Ticket Operations') { should_not eq 'No Auditing' }
  end
end

control 'windows-audit-203' do
  impact 1.0
  title 'Account Logon Audit Log'
  desc '
    policy_name: Audit Other Account Logon Events
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon
  '
  describe audit_policy do
    its('Other Account Logon Events') { should_not eq 'No Auditing' }
  end
end

control 'windows-audit-204' do
  impact 1.0
  title 'Audit Application Group Management'
  desc '
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management
  '
  describe audit_policy do
    its('Application Group Management') { should_not eq 'No Auditing' }
  end
end

control 'windows-audit-205' do
  impact 1.0
  title 'Audit Computer Account Management'
  desc '
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management
  '
  describe audit_policy do
    its('Computer Account Management') { should_not eq 'No Auditing' }
  end
end

control 'windows-audit-206' do
  impact 1.0
  title 'Audit Distributed Group Management'
  desc '
    policy_path: Computer Configuration\Windows Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management
  '
  describe audit_policy do
    its('Distribution Group Management') { should_not eq 'No Auditing' }
  end
end
