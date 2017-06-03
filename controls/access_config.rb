# encoding: utf-8

title 'Windows Access Configuration'

control 'windows-base-100' do
  impact 1.0
  title 'Verify the Windows folder permissions are properly set'
  describe file('c:/windows') do
    it { should be_directory }
    # it { should_not be_readable }
    # it { should_not be_writable.by('Administrator') }
  end
end

## NTLM

control 'windows-base-101' do
  impact 1.0
  title 'Safe DLL Search Mode is Enabled'
  desc '
    cannot be managed via group policy
    @link: https://msdn.microsoft.com/en-us/library/ms682586(v=vs.85).aspx
    @link: https://technet.microsoft.com/en-us/library/dd277307.aspx
  '
  describe registry_key('HKLM\System\CurrentControlSet\Control\Session Manager') do
    it { should exist }
    it { should_not have_property_value('SafeDllSearchMode', :type_dword, '0') }
  end
end

# MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
# Ensure voulmes are using the NTFS file systems
control 'windows-base-102' do
  impact 1.0
  title 'Anonymous Access to Windows Shares and Named Pipes is Disallowed'
  tag cis: ['windows_2012r2:2.3.11.8', 'windows_2016:2.3.10.9']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

control 'windows-base-103' do
  impact 1.0
  title 'All Shares are Configured to Prevent Anonymous Access'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('NullSessionShares') { should eq [''] }
  end
end

control 'windows-base-104' do
  impact 1.0
  title 'Force Encrypted Windows Network Passwords'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

control 'windows-base-105' do
  title 'SMB1 to Windows Shares is disabled'
  desc 'All Windows Shares are Configured to disable the SMB1 protocol'
  impact 1.0
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('SMB1') { should eq 0 }
  end
end

## LSA Authentication
# @link: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326(v=vs.85).aspx

control 'windows-base-201' do
  impact 1.0
  title 'Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled'
  desc '
    @link: http://support.microsoft.com/en-us/kb/823659
  '
  ref url: 'https://technet.microsoft.com/en-us/library/cc960646.aspx'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('LmCompatibilityLevel') { should > 4 }
  end
end

control 'windows-base-202' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Clients'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NtlmMinClientSec') { should > 537_395_200 }
  end
end

control 'windows-base-203' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Servers'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NtlmMinServerSec') { should > 537_395_200 }
  end
end
