# encoding: utf-8

laps_present = attribute('laps_present', default: true, description: 'Should we control presence of Microsoft laps')

if laps_present
  title 'Microsoft LAPS'
  control 'laps-1' do
  impact 0.7
  title 'laps - local password management'
  ref url: 'https://technet.microsoft.com/en-us/mt227395.aspx'
  ref url: 'https://adsecurity.org/?p=1790'
  ref url: 'http://www.petenetlive.com/KB/Article/0001059'
  escribe file('c:/Program Files/LAPS/CSE/AdmPwd.dll') do
    it { should be_file }
  end
  describe registry_key('HKLM\Software\Microsoft\Policies\Microsoft Services\AdmPwd') do
    it { should exist }
    its('AdmPwdEnabled') { should eq 1 }
  end
end
