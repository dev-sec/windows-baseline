# encoding: utf-8

title 'Windows Privacy'

control 'microsoft-online-accounts' do
  impact 1.0
  title 'Microsoft Online Accounts'
  desc 'Disabling Microsoft account logon sign-in option, eg. logging in without having to use local credentials and using microsoft online accounts'
  ref 'Block Microsoft Accounts', url: 'https://technet.microsoft.com/en-us/library/jj966262(v=ws.11).aspx'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount') do
    it { should exist }
    its('value') { should eq 0 }
  end
end

control 'disable-windows-store' do
  impact 1.0
  title 'Disable Windows Store'
  desc 'Ensure Turn off Automatic Download and Install ofupdates is set to Disabled'
  tag cis: '18.9.61.1'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore') do
    it { should exist }
    its('AutoDownload') { should eq 4 }
    its('DisableOSUpgrade') { should eq 1 }
  end
end

control 'disable-index-encrypted-files' do
  impact 1.0
  title 'Disable indexing encrypted files'
  desc 'Ensure Allow indexing of encrypted files is set to Disabled'
  tag cis: '18.9.54.2'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    it { should exist }
    its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
  end
end
