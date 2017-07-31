# encoding: utf-8

title 'Windows Suspicious extensions'

control 'wsh-101' do
  impact 1.0
  title 'Review potentially dangerous extensions association'
  ref url: 'https://bluesoul.me/2016/05/12/use-gpo-to-change-the-default-behavior-of-potentially-malicious-file-extensions/'
  describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.hta') do
    it { should exist }
    its('(Default)') { should eq '%windir%\system32\notepad.exe' }
  end
  describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs') do
    it { should exist }
    its('(Default)') { should eq '%windir%\system32\notepad.exe' }
  end
  describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.VBE') do
    it { should exist }
    its('(Default)') { should eq '%windir%\system32\notepad.exe' }
  end
  describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js') do
    it { should exist }
    its('(Default)') { should eq '%windir%\system32\notepad.exe' }
  end
  describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pif') do
    it { should exist }
    its('(Default)') { should eq '%windir%\system32\notepad.exe' }
  end
end
