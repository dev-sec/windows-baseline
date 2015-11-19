# encoding: utf-8
# copyright: 2015, Vulcano Security GmbH
# license: All rights reserved
# title: Windows Audit & Logging Configuration

rule 'windows-base-100' do
  impact 1.0
  title 'Verify the Windows folder permissions are properly set'
  describe file('c:/windows') do
    it { should be_directory }
    # it { should_not be_readable }
    # it { should_not be_writable.by('Administrator') }
  end
end

## NTLM

rule 'windows-base-101' do
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

rule 'windows-base-102' do
  impact 1.0
  title 'Anonymous Access to Windows Shares and Named Pipes is Disallowed'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('restrictnullsessaccess') { should eq 1 }
  end
end

rule 'windows-base-103' do
  impact 1.0
  title 'All Shares are Configured to Prevent Anonymous Access'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('NullSessionShares') { should eq nil }
  end
end

rule 'windows-base-104' do
  impact 1.0
  title 'Force Encrypted Windows Network Passwords'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

## LSA Authentication
# @link: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326(v=vs.85).aspx

rule 'windows-base-201' do
  impact 1.0
  title 'Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled'
  desc '
    @link: http://support.microsoft.com/en-us/kb/823659
  '
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('LmCompatibilityLevel') { should eq 4 }
  end
end

rule 'windows-base-202' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Clients'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NTLMMinClientSec') { should eq 537395200 }
  end
end

rule 'windows-base-203' do
  impact 1.0
  title 'Enable Strong Encryption for Windows Network Sessions on Servers'
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('NTLMMinServerSec') { should eq 537395200 }
  end
end
