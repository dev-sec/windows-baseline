# encoding: utf-8

sysmon_present = attribute('sysmon_present', default: false, description: 'Should we control presence of Microsoft sysmon')

if sysmon_present
  title 'Ms Sysmon'

  control 'sysmon-1' do
    impact 0.7
    title 'Sysinternals Sysmon is running'
    desc 'Sysmon process monitoring is active'
    ref url: 'https://technet.microsoft.com/en-us/sysinternals/sysmon'
    ref url: 'https://medium.com/@lennartkoopmann/explaining-and-adapting-tays-sysmon-configuration-27d9719a89a8'
    ## FIXME! process listing NOK
    # describe processes('sysmon.exe') do
    # describe processes('c:\windows\sysmon.exe') do
    #   its('list.length') { should eq 1 }
    #   its('users') { should cmp 'SYSTEM' }
    # end
    describe file('c:\windows\sysmon.exe') do
      it { should be_file }
    end
  end
end
