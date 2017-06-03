# encoding: utf-8

title 'Windows PowerShell'

powershellblocklogging_enabled = attribute('powershellblocklogging_enabled', default: false, description: 'Should we control Powershell Script Block Logging as enabled or not')
powershelltranscription_enabled = attribute('powershelltranscription_enabled', default: false, description: 'Should we control Powershell Transcription as enabled or not')

## FIXME! can we test powershell v5+ is installed? seems only windows_feature

control 'powershell-module-logging' do
  impact 1.0
  title 'PowerShell Module Logging'
  desc 'Enabling PowerShell Module Logging will record executed scripts'
  ref url: 'https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html'
  describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging') do
    it { should exist }
    its('EnableModuleLogging') { should eq 1 }
  end
  describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging \ModuleNames') do
    it { should exist }
    its('*') { should eq '*' }
  end
end

if powershellblocklogging_enabled
  control 'powershell-script-blocklogging' do
    impact 1.0
    title 'PowerShell Script Block Logging'
    desc 'Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts'
    ref url: 'https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html'
    describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
      it { should exist }
      its('EnableScriptBlockLogging') { should eq 1 }
    end
  end
else
  control 'powershell-script-blocklogging' do
    impact 1.0
    title 'PowerShell Script Block Logging'
    desc 'Disabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts'
    tag cis: '18.9.84.1'
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
    describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
      it { should exist }
      its('EnableScriptBlockLogging') { should eq 0 }
    end
  end
end

if powershelltranscription_enabled
  control 'powershell-transcription' do
    impact 1.0
    title 'PowerShell Transcription'
    desc 'Transcription creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session.'
    ref url: 'https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html'
    describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription') do
      it { should exist }
      its('EnableTranscripting') { should eq 1 }
    end
  end
else
  control 'powershell-transcription' do
    impact 1.0
    title 'PowerShell Transcription'
    desc 'Transcription creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session.'
    tag cis: '18.9.84.2'
    ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
    describe registry_key('HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription') do
      it { should exist }
      its('EnableTranscripting') { should eq 0 }
    end
  end
end

control 'powershell-remove-v2' do
  impact 1.0
  title 'PowerShell v2 not present'
  desc 'Avoid attacks downgrading Powershell v2 by uninstalling older releases'
  ref url: 'http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/'
  # no DSIM on default win10?
  # describe command('DSIM /online /get-feature /format-table | findstr /i MicrosoftWindowsPowerShellV2 | findstr Disabled') do
  #   its('stdout') { should_not eq '' }
  # end
  # describe command('DSIM /online /get-feature /format-table | findstr /i MicrosoftWindowsPowerShellV2Root | findstr Disabled') do
  #   its('stdout') { should_not eq '' }
  # end
  describe powershell('Get-WindowsOptionalFeature -Online | where FeatureName -eq MicrosoftWindowsPowerShellV2') do
    its('stdout') { should include 'Disabled' }
  end
  describe powershell('Get-WindowsOptionalFeature -Online | where FeatureName -eq MicrosoftWindowsPowerShellV2Root') do
    its('stdout') { should include 'Disabled' }
  end
end
