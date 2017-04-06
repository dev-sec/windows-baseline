# encoding: utf-8

title 'Windows PowerShell'

control 'powershell-script-blocklogging' do
  impact 1.0
  title 'PowerShell Script Block Logging'
  desc 'Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts'
  tag cis: '18.9.84.1'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    it { should exist }
    its('EnableScriptBlockLogging') { should eq 0 }
  end
end

control 'powershell-transcription' do
  impact 1.0
  title 'PowerShell Transcription'
  desc 'Transcription creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session.'
  tag cis: '18.9.84.2'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription') do
    it { should exist }
    its('EnableTranscripting') { should eq 0 }
  end
end
