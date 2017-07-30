# encoding: utf-8

wsus_check = attribute('wsus_check', default: false, description: 'Should we control configuration of WSUS server')

if wsus_check
  title 'Microsoft WSUS configuration'

  control 'wsus-1' do
    impact 0.7
    title 'Ms WSUS'
    desc 'Microsoft WSUS configured either with GPO, either registry'
    ref url: 'https://technet.microsoft.com/en-us/library/cc708449(v=ws.10).aspx'
    describe registry_key('HKEY_LOCAL_MACHINE:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') do
      it { should exist }
      its('WUServer') { should_not eq '' }
      its('WUStatusServer') { should_not eq '' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU') do
      it { should exist }
    end
  end

end
