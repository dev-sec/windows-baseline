# encoding: utf-8

title 'Windows SMB configuration'

control 'smb-101' do
  impact 1.0
  title 'Disable Old SMBv1'
  ref url: 'https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices'
  ref url: 'https://support.microsoft.com/en-ca/help/2696547/how-to-enable-and-disable-smbv1,-smbv2,-and-smbv3-in-windows-vista,-windows-server-2008,-windows-7,-windows-server-2008-r2,-windows-8,-and-windows-server-2012'
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') do
    it { should exist }
    its('SMB1') { should eq 0 }
  end
  # no DSIM on default win10?
  # describe command('DSIM /online /get-feature /format-table | findstr /i SMB1Protocol | findstr Disabled') do
  #   its('stdout') { should_not eq '' }
  # end
  describe powershell('Get-WindowsOptionalFeature -Online | where FeatureName -eq SMB1Protocol') do
    # Disabled or DisablePending
    its('stdout') { should include 'Disable' }
  end
end
