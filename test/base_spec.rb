# encoding: utf-8
# copyright: 2015, Vulcano Security GmbH
# license: All rights reserved
# title: Windows Audit & Logging Configuration

rule "windows-base-100" do
  impact 1.0
  title "Verify the Windows folder permissions are properly set"
  describe file("c:/windows") do
    it { should be_directory }
    it { should_not be_readable }
    it { should_not be_writable.by("Administrator") }
  end
end

## NTLM

rule "windows-base-101" do
  impact 1.0
  title "Safe DLL Search Mode is Enabled"
  desc "
    cannot be managed via group policy
    @link: https://msdn.microsoft.com/en-us/library/ms682586(v=vs.85).aspx
    @link: https://technet.microsoft.com/en-us/library/dd277307.aspx
  "
  describe registry_key("HKLM\\System\\CurrentControlSet\\Control\\Session Manager") do
    it { should exist }
    it { should_not have_property_value("SafeDllSearchMode", :type_dword, "0") }
  end
end

# MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
# Ensure voulmes are using the NTFS file systems

rule "windows-base-102" do
  impact 1.0
  title "Anonymous Access to Windows Shares and Named Pipes is Disallowed"
  describe group_policy("Local Policies\\Security Options") do
    its("Network access: Restrict anonymous access to Named Pipes and Shares") { should eq 1 }
  end
end

rule "windows-base-103" do
  impact 1.0
  title "All Shares are Configured to Prevent Anonymous Access"
  describe group_policy("Local Policies\\Security Options") do
    its("Network access: Shares that can be accessed anonymously") { should eq nil }
  end
end

rule "windows-base-104" do
  impact 1.0
  title "Force Encrypted Windows Network Passwords"
  describe group_policy("Local Policies\\Security Options") do
    its("Microsoft network client: Send unencrypted password to third-party SMB servers") { should eq 0 }
  end
end

## LSA Authentication
# @link: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378326(v=vs.85).aspx

rule "windows-base-201" do
  impact 1.0
  title "Strong Windows NTLMv2 Authentication Enabled; Weak LM Disabled"
  desc "
    @link: http://support.microsoft.com/en-us/kb/823659
  "
  describe group_policy("Local Policies\\Security Options") do
    its("Network security: LAN Manager authentication level") { should eq 4 }
  end
end

rule "windows-base-202" do
  impact 1.0
  title "Enable Strong Encryption for Windows Network Sessions on Clients"
  describe group_policy("Local Policies\\Security Options") do
    its("Network security: Minimum session security for NTLM SSP based (including secure RPC) clients") { should eq 537395200 }
  end
end

rule "windows-base-203" do
  impact 1.0
  title "Enable Strong Encryption for Windows Network Sessions on Servers"
  describe group_policy("Local Policies\\Security Options") do
    its("Network security: Minimum session security for NTLM SSP based (including secure RPC) servers") { should eq 537395200 }
  end
end
