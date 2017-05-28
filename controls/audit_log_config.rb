# encoding: utf-8

title 'Windows Audit & Logging Configuration'

control 'windows-audit-100' do
  impact 0.1
  title 'Configure System Event Log (Application)'
  desc 'Only applies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Application') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
  ## Win7
  describe registry_key('HKLM\System\CurrentControlSet\Services\EventLog\Application') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-101' do
  impact 0.1
  title 'Configure System Event Log (Security)'
  desc 'Only applies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Security') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
  describe registry_key('HKLM\System\CurrentControlSet\Services\EventLog\Security') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-102' do
  impact 0.1
  title 'Configure System Event Log (Setup)'
  desc 'Only applies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
end

control 'windows-audit-103' do
  impact 0.1
  title 'Configure System Event Log (System)'
  desc 'Only applies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\System') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
  describe registry_key('HKLM\System\CurrentControlSet\Services\EventLog\System') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-104' do
  impact 0.1
  title 'Configure System Event Log (Windows PowerShell)'
  desc 'Only applies for Windows 2008 and newer'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\EventLog\Windows PowerShell') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
  end
  describe registry_key('HKLM\System\CurrentControlSet\Services\EventLog\Windows PowerShell') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-105' do
  impact 0.1
  title 'Configure System Event Log (Channels - Windows PowerShell)'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-106' do
  impact 0.1
  title 'Configure System Event Log (Channels - Windows-WMI)'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI/Operational') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
  end
end

control 'windows-audit-107' do
  impact 0.1
  title 'Configure System Event Log (Channels - Sysmon)'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational') do
    it { should exist }
    its('MaxSize') { should_not eq nil }
    its('MaxSize') { should >= 315801600 }
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
  tag cis: ['windows_2012r2:17.2.2', 'windows_2016L:17.2.2']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark'
  describe audit_policy do
    its('Computer Account Management') { should eq 'Success and Failure' }
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

control 'windows-audit-207' do
  impact 1.0
  title 'Audit Process Cmdline'
  desc 'Command line data must be included in process creation events'
  ref url: 'https://www.stigviewer.com/stig/windows_8_8.1/2014-06-27/finding/V-43239'
  describe registry_key('HKEY_LOCAL_MACHINE:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    it { should exist }
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 1 }
  end
end

control 'windows-audit-208' do
  impact 1.0
  title 'Audit LSA plugins and drivers'
  desc 'How to identify plug-ins and drivers loaded by the lsass.exe'
  ref url: 'https://adsecurity.org/?p=3299'
  describe registry_key('HKEY_LOCAL_MACHINE:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe') do
    it { should exist }
    its('AuditLevel') { should eq 8 }
  end
end
