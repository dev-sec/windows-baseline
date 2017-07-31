# encoding: utf-8

emet_present = attribute('emet_present', default: false, description: 'Should we control presence of Microsoft EMET')

if emet_present
  title 'Ms EMET'

  control 'EMET-1' do
    impact 0.7
    title 'Ms EMET is running'
    desc 'EMET process monitoring is active'
    ref url: 'https://insights.sei.cmu.edu/cert/2016/11/windows-10-cannot-protect-insecure-applications-like-emet-can.html'
    ref url: 'https://www.stigviewer.com/stig/windows_8_8.1/2014-06-27/finding/V-39137'
    describe processes('EMET_Service.exe') do
      its('list.length') { should eq 1 }
      its('users') { should cmp 'SYSTEM' }
    end
    describe processes('EMET_Agent.exe') do
      its('list.length') { should eq 1 }
    end
  end
end
