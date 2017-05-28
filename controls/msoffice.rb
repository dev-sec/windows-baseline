# encoding: utf-8

msoffice_present = attribute('msoffice_present', default: false, description: 'Should we control presence of Microsoft msoffice')

if msoffice_present?
  title 'Microsoft office'

  control 'msoffice-1' do
    impact 0.7
    title 'Ms Office'
    desc 'Hardening of Microsoft Office, either with GPO, either registry'
    ref url: 'https://www.asd.gov.au/publications/protect/hardening-ms-office-2016.htm'
    ref url: 'https://www.asd.gov.au/publications/protect/ms-office-macro-security.htm'
    describe security_policy do
      its('SeRemoteInteractiveLogonRight') { should eq '*S-1-5-32-544' }
    end
  end

  control 'msoffice-2' do
    impact 0.7
    title 'Outlook'
    desc 'silently disable OLE Package function in Outlook'
    ref url: 'https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0'
    describe registry_key('HKEY_CURRENT_USER:\SOFTWARE\Microsoft\Office\15.0\Outlook\Security') do
      it { should exist }
      its('ShowOLEPackageObj') { should eq 0 }
    end
  end

  control 'msproject-1' do
    impact 0.7
    title 'Ms Project'
    desc 'Disable Macros with notifications'
    ref url: 'https://blogs.technet.microsoft.com/diana_tudor/2014/12/02/microsoft-project-how-to-control-macro-settings-using-registry-keys/'
    describe registry_key('HKEY_CURRENT_USER:\SOFTWARE\Policies\Microsoft\Office\15.0\msproject\Security') do
      it { should exist }
      its('VBAWarnings') { should >= 2 }
    end
  end
end
