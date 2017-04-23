# encoding: utf-8

title 'Ms Sysmon'

control 'sysmon-1' do
  impact 0.7
  title 'Sysinternals Sysmon is running'
  desc 'Sysmon process monitoring is active'
  ## FIXME! process listing NOK
  describe processes('sysmon.exe') do
    # describe processes('c:\windows\sysmon.exe') do
    its('list.length') { should eq 1 }
    # its('users') { should cmp 'SYSTEM' }
  end
end
