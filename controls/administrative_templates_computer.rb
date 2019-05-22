title 'Administrative Templates (Computer)'

control 'windows-175' do
  title 'Ensure \'Prevent enabling lock screen camera\' is set to \'Enabled\''
  desc 'Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.1.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should exist }
    it { should have_property 'NoLockScreenCamera' }
    its('NoLockScreenCamera') { should eq 1 }
  end
end

control 'windows-176' do
  title 'Ensure \'Prevent enabling lock screen slide show\' is set to \'Enabled\''
  desc 'Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.1.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should exist }
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should eq 1 }
  end
end

control 'windows-177' do
  title 'Ensure \'Allow Input Personalization\' is set to \'Disabled\''
  desc 'This policy enables the automatic learning component of input personalization that includes speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns, typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some of this collected information may be stored on the user\'s OneDrive, in the case of inking and typing; some of the information will be uploaded to Microsoft to personalize speech.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization') do
    it { should exist }
    it { should have_property 'AllowInputPersonalization' }
    its('AllowInputPersonalization') { should eq 0 }
  end
end

control 'windows-178' do
  title 'Ensure \'Allow Online Tips\' is set to \'Disabled\''
  desc 'This policy setting configures the retrieval of online tips and help for the Settings app.

  The recommended state for this setting is: Disabled. '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'AllowOnlineTips' }
    its('AllowOnlineTips') { should eq 0 }
  end
end

control 'windows-179' do
  title 'Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}') do
    it { should exist }
    it { should have_property 'DllName' }
    its('DllName') { should eq 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll' }
  end
end

control 'windows-180' do
  title 'Ensure \'Do not allow password expiration time longer than required by policy\' is set to \'Enabled\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PwdExpirationProtectionEnabled' }
    its('PwdExpirationProtectionEnabled') { should eq 1 }
  end
end

control 'windows-181' do
  title 'Ensure \'Enable Local Admin Password Management\' is set to \'Enabled\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'AdmPwdEnabled' }
    its('AdmPwdEnabled') { should eq 1 }
  end
end

control 'windows-182' do
  title 'Ensure \'Password Settings: Password Complexity\' is set to \'Enabled: Large letters + small letters + numbers + special characters\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: Large letters + small letters + numbers + special characters.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordComplexity' }
    its('PasswordComplexity') { should eq 4 }
  end
end

control 'windows-183' do
  title 'Ensure \'Password Settings: Password Length\' is set to \'Enabled: 15 or more\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: 15 or more.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordLength' }
    its('PasswordLength') { should be >= 15 }
  end
end

control 'windows-184' do
  title 'Ensure \'Password Settings: Password Age (Days)\' is set to \'Enabled: 30 or fewer\' (MS only)'
  desc 'In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

  The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

  LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

  The recommended state for this setting is: Enabled: 30 or fewer.

  **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should exist }
    it { should have_property 'PasswordAgeDays' }
    its('PasswordAgeDays') { should be <= 30 }
  end
end

control 'windows-185' do
  title 'Ensure \'Apply UAC restrictions to local accounts on network logons\' is set to \'Enabled\' (MS only)'
  desc 'This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.

  **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.

  **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1.

  For more information about local accounts and credential theft, review the [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) documents.

  For more information about LocalAccountTokenFilterPolicy, see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LocalAccountTokenFilterPolicy' }
    its('LocalAccountTokenFilterPolicy') { should eq 0 }
  end
end

control 'windows-186' do
  title 'Ensure \'Configure SMB v1 client driver\' is set to \'Enabled: Disable driver\''
  desc 'This setting configures the start type for the Server Message Block version 1 (SMBv1) client driver service (MRxSmb10), which is recommended to be disabled.

  The recommended state for this setting is: Enabled: Disable driver.

  **Note:** Do not, **under any circumstances**, configure this overall setting as Disabled, as doing so will delete the underlying registry entry altogether, which will cause serious problems.

  Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

  More information on this can be found at the following links:

  [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

  [Disable SMB v1 in Managed Environments with Group Policy &#x2013; Stay Safe Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

  [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-187' do
  title 'Ensure \'Configure SMB v1 server\' is set to \'Disabled\''
  desc 'This setting configures the server-side processing of the Server Message Block version 1 (SMBv1) protocol.

  The recommended state for this setting is: Disabled.

  Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

  More information on this can be found at the following links:

  [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

  [Disable SMB v1 in Managed Environments with Group Policy &#x2013; Stay Safe Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

  [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/)'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should exist }
    it { should have_property 'SMB1' }
    its('SMB1') { should eq 0 }
  end
end

control 'windows-188' do
  title 'Ensure \'Enable Structured Exception Handling Overwrite Protection (SEHOP)\' is set to \'Enabled\''
  desc 'Windows includes support for Structured Exception Handling Overwrite Protection (SEHOP). We recommend enabling this feature to improve the security profile of the computer.

  The recommended state for this setting is: Enabled.

  Rationale: This feature is designed to block exploits that use the Structured Exception Handler (SEH) overwrite technique. This protection mechanism is provided at run-time. Therefore, it helps protect applications regardless of whether they have been compiled with the latest improvements, such as the /SAFESEH option.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel') do
    it { should exist }
    it { should have_property 'DisableExceptionChainValidation' }
    its('DisableExceptionChainValidation') { should eq 0 }
  end
end

control 'windows-189' do
  title 'Ensure \'WDigest Authentication\' is set to \'Disabled\''
  desc 'When WDigest authentication is enabled, Lsass.exe retains a copy of the user\'s plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.

  For more information about local accounts and credential theft, review the [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) documents.

  For more information about UseLogonCredential, see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.3.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest') do
    it { should exist }
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should eq 0 }
  end
end

control 'windows-191' do
  title 'Ensure \'Turn on Windows Defender protection against Potentially Unwanted Applications\' is set to \'Enabled\''
  desc 'Enabling this Windows Defender feature will protect against Potentially Unwanted Applications (PUA), which are sneaky unwanted application bundlers or their bundled applications to deliver adware or malware.
  The recommended state for this setting is: Enabled.
  For more information, see this link: [Block Potentially Unwanted Applications with Windows Defender AV | Microsoft Docs](https://docs.microsoft.com/de-de/windows/security/threat-protection/windows-defender-antivirus/detect-block-potentially-unwanted-apps-windows-defender-antivirus)'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.3.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine') do
    it { should exist }
    it { should have_property 'MpEnablePus' }
    its('MpEnablePus') { should eq 1 }
  end
end

control 'windows-192' do
  title 'Ensure \'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)\' is set to \'Disabled\''
  desc 'This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.

  For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'AutoAdminLogon' }
    its('AutoAdminLogon') { should eq 0 }
  end
end

control 'windows-193' do
  title 'Ensure \'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)\' is set to \'Enabled: Highest protection, source routing is completely disabled\''
  desc 'IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.

  The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    it { should exist }
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

control 'windows-194' do
  title 'Ensure \'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\' is set to \'Enabled: Highest protection, source routing is completely disabled\''
  desc 'IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.

  The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should eq 2 }
  end
end

control 'windows-195' do
  title 'Ensure \'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\' is set to \'Disabled\''
  desc 'Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should eq 0 }
  end
end

control 'windows-196' do
  title 'Ensure \'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds\' is set to \'Enabled: 300,000 or 5 minutes (recommended)\''
  desc 'This value controls how often TCP attempts to verify that an idle connection is still intact by sending a keep-alive packet. If the remote computer is still reachable, it acknowledges the keep-alive packet.

  The recommended state for this setting is: Enabled: 300,000 or 5 minutes (recommended).'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.5'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'KeepAliveTime' }
    its('KeepAliveTime') { should eq 300000 }
  end
end

control 'windows-197' do
  title 'Ensure \'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers\' is set to \'Enabled\''
  desc 'NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    it { should exist }
    it { should have_property 'nonamereleaseondemand' }
    its('nonamereleaseondemand') { should eq 1 }
  end
end

control 'windows-198' do
  title 'Ensure \'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)\' is set to \'Disabled\''
  desc 'This setting is used to enable or disable the Internet Router Discovery Protocol (IRDP), which allows the system to detect and configure default gateway addresses automatically as described in RFC 1256 on a per-interface basis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.7'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'PerformRouterDiscovery' }
    its('PerformRouterDiscovery') { should eq 0 }
  end
end

control 'windows-199' do
  title 'Ensure \'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)\' is set to \'Enabled\''
  desc 'The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:

  * Search folders specified in the system path first, and then search the current working folder.
  * Search current working folder first, and then search the folders specified in the system path.
  When enabled, the registry value is set to 1. With a setting of 1, the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.

  Applications will be forced to search for DLLs in the system path first. For applications that require unique versions of these DLLs that are included with the application, this entry could cause performance or stability problems.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should exist }
    it { should have_property 'SafeDllSearchMode' }
    its('SafeDllSearchMode') { should eq 1 }
  end
end

control 'windows-200' do
  title 'Ensure \'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)\' is set to \'Enabled: 5 or fewer seconds\''
  desc ' Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.

  The recommended state for this setting is: Enabled: 5 or fewer seconds.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ScreenSaverGracePeriod' }
    its('ScreenSaverGracePeriod') { should be <= 5 }
  end
end

control 'windows-201' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\''
  desc 'This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

  The recommended state for this setting is: Enabled: 3.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.10'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should exist }
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should eq 3 }
  end
end

control 'windows-202' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\''
  desc 'This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

  The recommended state for this setting is: Enabled: 3.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.11'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should exist }
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should eq 3 }
  end
end

control 'windows-203' do
  title 'Ensure \'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning\' is set to \'Enabled: 90% or less\''
  desc 'This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.

  The recommended state for this setting is: Enabled: 90% or less.

  **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.4.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.4.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    it { should exist }
    it { should have_property 'WarningLevel' }
    its('WarningLevel') { should be <= 90 }
  end
end

control 'windows-204' do
  title 'Set \'NetBIOS node type\' to \'P-node\' (Ensure NetBT Parameter \'NodeType\' is set to \'0x2 (2)\') (MS Only)'
  desc 'This parameter determines which method NetBIOS over TCP/IP (NetBT) will use to register and resolve names.

  * A B-node (broadcast) system only uses broadcasts.
  * A P-node (point-to-point) system uses only name queries to a name server (WINS).
  * An M-node (mixed) system broadcasts first, then queries the name server (WINS).
  * An H-node (hybrid) system queries the name server (WINS) first, then broadcasts.
  The recommended state for this setting is: NodeType - 0x2 (2).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.4.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters') do
    it { should have_property 'NodeType' }
    its('NodeType') { should eq 2 }
  end
end

control 'windows-205' do
  title 'Ensure \'Turn off multicast name resolution\' is set to \'Enabled\' (MS Only)'
  desc 'LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using multicast over a local network link on a single subnet from a client computer to another client computer on the same subnet that also has LLMNR enabled. LLMNR does not require a DNS server or DNS client configuration, and provides name resolution in scenarios in which conventional DNS name resolution is not possible.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.4.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient') do
    it { should have_property 'EnableMulticast' }
    its('EnableMulticast') { should eq 0 }
  end
end

control 'windows-206' do
  title ' Ensure \'Enable Font Providers\' is set to \'Disabled\''
  desc 'This policy setting determines whether Windows is allowed to download fonts and font catalog data from an online font provider.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.5.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableFontProviders' }
    its('EnableFontProviders') { should eq 0 }
  end
end

control 'windows-207' do
  title 'Ensure \'Enable insecure guest logons\' is set to \'Disabled\''
  desc 'This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    it { should exist }
    it { should have_property 'AllowInsecureGuestAuth' }
    its('AllowInsecureGuestAuth') { should eq 0 }
  end
end

control 'windows-208' do
  title 'Ensure \'Turn on Mapper I/O (LLTDIO) driver\' is set to \'Disabled\''
  desc 'This policy setting changes the operational behavior of the Mapper I/O network protocol driver.

  LLTDIO allows a computer to discover the topology of a network it\'s connected to. It also allows a computer to initiate Quality-of-Service requests such as bandwidth estimation and network health analysis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.9.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowLLTDIOOndomain' }
    its('AllowLLTDIOOndomain') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowLLTDIOOnPublicNet' }
    its('AllowLLTDIOOnPublicNet') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'EnableLLTDIO' }
    its('EnableLLTDIO') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'ProhibitLLTDIOOnPrivateNet' }
    its('ProhibitLLTDIOOnPrivateNet') { should eq 0 }
  end
end

control 'windows-209' do
  title 'Ensure \'Turn on Responder (RSPNDR) driver\' is set to \'Disabled\''
  desc 'This policy setting changes the operational behavior of the Responder network protocol driver.

  The Responder allows a computer to participate in Link Layer Topology Discovery requests so that it can be discovered and located on the network. It also allows a computer to participate in Quality-of-Service activities such as bandwidth estimation and network health analysis.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.9.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowRspndrOndomain' }
    its('AllowRspndrOndomain') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'AllowRspndrOnPublicNet' }
    its('AllowRspndrOnPublicNet') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'EnableRspndr' }
    its('EnableRspndr') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should exist }
    it { should have_property 'ProhibitRspndrOnPrivateNet' }
    its('ProhibitRspndrOnPrivateNet') { should eq 0 }
  end
end

control 'windows-210' do
  title 'Ensure \'Turn off Microsoft Peer-to-Peer Networking Services\' is set to \'Enabled\''
  desc 'The Peer Name Resolution Protocol (PNRP) allows for distributed resolution of a name to an IPv6 address and port number. The protocol operates in the context of **clouds**. A cloud is a set of peer computers that can communicate with each other by using the same IPv6 scope.

  Peer-to-Peer protocols allow for applications in the areas of RTC, collaboration, content distribution and distributed processing.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.10.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet') do
    it { should exist }
    it { should have_property 'Disabled' }
    its('Disabled') { should eq 1 }
  end
end

control 'windows-211' do
  title 'Ensure \'Prohibit installation and configuration of Network Bridge on your DNS domain network\' is set to \'Enabled\''
  desc 'You can use this procedure to controls user\'s ability to install and configure a Network Bridge.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_AllowNetBridge_NLA' }
    its('NC_AllowNetBridge_NLA') { should eq 0 }
  end
end

control 'windows-212' do
  title 'Ensure \'Prohibit use of Internet Connection Sharing on your DNS domain network\' is set to \'Enabled\''
  desc 'Although this "legacy" setting traditionally applied to the use of Internet Connection Sharing (ICS) in Windows 2000, Windows XP & Server 2003, this setting now freshly applies to the Mobile Hotspot feature in Windows 10 & Server 2016.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should eq 0 }
  end
end

control 'windows-213' do
  title 'Ensure \'Require domain users to elevate when setting a network\'s location\' is set to \'Enabled\''
  desc 'This policy setting determines whether to require domain users to elevate when setting a network\'s location.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.11.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.11.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should exist }
    it { should have_property 'NC_StdDomainUserSetLocation' }
    its('NC_StdDomainUserSetLocation') { should eq 1 }
  end
end

control 'windows-214' do
  title 'Ensure \'Hardened UNC Paths\' is set to \'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares\''
  desc 'This policy setting configures secure access to UNC paths.

  The recommended state for this setting is: Enabled, with \'Require Mutual Authentication\' and \'Require Integrity\' set for all NETLOGON and SYSVOL shares.

  **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 or higher systems, then the \'Privacy\' setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.

  Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of the [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483) security update. This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Windows Vista / Server 2008 (non-R2) or higher (the associated security patch to enable this feature was not released for Server 2003). A new group policy template (NetworkProvider.admx/adml) was also provided with the security update.

  Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk:

  \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1\\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1

  **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.

  Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.14.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should exist }
    it { should have_property '\\\*\\NETLOGON' }
    it { should have_property '\\\*\\SYSVOL' }
    its('\\\*\\NETLOGON') { should match(//) }
    its('\\\*\\SYSVOL') { should match(//) }
  end
end

control 'windows-215' do
  title 'Disable IPv6 (Ensure TCPIP6 Parameter \'DisabledComponents\' is set to \'0xff (255)\')'
  desc 'Internet Protocol version 6 (IPv6) is a set of protocols that computers use to exchange information over the Internet and over home and business networks. IPv6 allows for many more IP addresses to be assigned than IPv4 did. Older networking, hosts and operating systems may not support IPv6 natively.

  The recommended state for this setting is: DisabledComponents - 0xff (255)'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.19.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.19.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should exist }
    it { should have_property 'DisabledComponents' }
    its('DisabledComponents') { should eq 255 }
  end
end

control 'windows-216' do
  title 'Ensure \'Configuration of wireless settings using Windows Connect Now\' is set to \'Disabled\''
  desc 'This policy setting allows the configuration of wireless settings using Windows Connect Now (WCN). The WCN Registrar enables the discovery and configuration of devices over Ethernet (UPnP) over in-band 802.11 Wi-Fi through the Windows Portable Device API (WPD) and via USB Flash drives. Additional options are available to allow discovery and configuration over a specific medium.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.20.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.20.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'EnableRegistrars' }
    its('EnableRegistrars') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableUPnPRegistrar' }
    its('DisableUPnPRegistrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableInBand802DOT11Registrar' }
    its('DisableInBand802DOT11Registrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableFlashConfigRegistrar' }
    its('DisableFlashConfigRegistrar') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should exist }
    it { should have_property 'DisableWPDRegistrar' }
    its('DisableWPDRegistrar') { should eq 0 }
  end
end

control 'windows-217' do
  title 'Ensure \'Prohibit access of the Windows Connect Now wizards\' is set to \'Enabled\''
  desc 'This policy setting prohibits access to Windows Connect Now (WCN) wizards.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.20.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.20.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI') do
    it { should exist }
    it { should have_property 'DisableWcnUi' }
    its('DisableWcnUi') { should eq 1 }
  end
end

control 'windows-218' do
  title 'Ensure \'Minimize the number of simultaneous connections to the Internet or a Windows Domain\' is set to \'Enabled\''
  desc 'This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.21.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.21.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should exist }
    it { should have_property 'fMinimizeConnections' }
    its('fMinimizeConnections') { should eq 1 }
  end
end

control 'windows-219' do
  title 'Ensure \'Prohibit connection to non-domain networks when connected to domain authenticated network\' is set to \'Enabled\' (MS only)'
  desc 'This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.5.21.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.5.21.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should eq 1 }
  end
end

control 'windows-220' do
  title 'Ensure \'Include command line in process creation events\' is set to \'Disabled\''
  desc 'This policy setting determines what information is logged in security audit events when a new process has been created.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit') do
    it { should exist }
    it { should have_property 'ProcessCreationIncludeCmdLine_Enabled' }
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 0 }
  end
end

control 'windows-221' do
  title 'Ensure \'Remote host allows delegation of non-exportable credentials\' is set to \'Enabled\''
  desc 'Remote host allows delegation of non-exportable credentials. When using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host. The Restricted Admin Mode and Windows Defender Remote Credential Guard features are two options to help protect against this risk.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation') do
    it { should have_property 'AllowProtectedCreds' }
    its('AllowProtectedCreds') { should eq 1 }
  end
end

control 'windows-222' do
  title 'Ensure \'Boot-Start Driver Initialization Policy\' is set to \'Enabled: Good, unknown and bad but critical\''
  desc 'This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:

  * Good: The driver has been signed and has not been tampered with.
  * Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
  * Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
  * Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
  If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.

  If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.

  The recommended state for this setting is: Enabled: Good, unknown and bad but critical.

  Rationale: This policy setting helps reduce the impact of malware that has already infected your system'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.14.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch') do
    it { should exist }
    it { should have_property 'DriverLoadPolicy' }
    its('DriverLoadPolicy') { should eq 3 }
  end
end

control 'windows-223' do
  title 'Ensure \'Configure registry policy processing: Do not apply during periodic background processing\' is set to \'Enabled: FALSE\''
  desc 'The \'Do not apply during periodic background processing\' option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.

  The recommended state for this setting is: Enabled: FALSE (unchecked).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property 'NoBackgroundPolicy' }
    its('NoBackgroundPolicy') { should eq 0 }
  end
end

control 'windows-224' do
  title 'Ensure \'Configure registry policy processing: Process even if the Group Policy objects have not changed\' is set to \'Enabled: TRUE\''
  desc 'The \'Process even if the Group Policy objects have not changed\' option updates and reapplies policies even if the policies have not changed.

  The recommended state for this setting is: Enabled: TRUE (checked).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should exist }
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should eq 0 }
  end
end

control 'windows-225' do
  title 'Ensure \'Continue experiences on this device\' is set to \'Disabled\''
  desc 'This policy setting determines whether the Windows device is allowed to participate in cross-device experiences (continue experiences).

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableCdp' }
    its('EnableCdp') { should eq 0 }
  end
end

control 'windows-226' do
  title 'Ensure \'Turn off background refresh of Group Policy\' is set to \'Disabled\''
  desc 'This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and Domain Controllers.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.21.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.21.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should_not have_property 'DisableBkGndGroupPolicy' }
  end
end

control 'windows-227' do
  title 'Ensure \'Turn off downloading of print drivers over HTTP\' is set to \'Enabled\''
  desc 'This policy setting controls whether the computer can download print driver packages over HTTP. To set up HTTP printing, printer drivers that are not available in the standard operating system installation might need to be downloaded over HTTP.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should exist }
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should eq 1 }
  end
end

control 'windows-228' do
  title 'Ensure \'Turn off handwriting personalization data sharing\' is set to \'Enabled\''
  desc 'This setting turns off data sharing from the handwriting recognition personalization tool.

  The handwriting recognition personalization tool enables Tablet PC users to adapt handwriting recognition to their own writing style by providing writing samples. The tool can optionally share user writing samples with Microsoft to improve handwriting recognition in future versions of Windows. The tool generates reports and transmits them to Microsoft over a secure connection.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TabletPC') do
    it { should exist }
    it { should have_property 'PreventHandwritingDataSharing' }
    its('PreventHandwritingDataSharing') { should eq 1 }
  end
end

control 'windows-229' do
  title 'Ensure \'Turn off handwriting recognition error reporting\' is set to \'Enabled\''
  desc 'Turns off the handwriting recognition error reporting tool.

  The handwriting recognition error reporting tool enables users to report errors encountered in Tablet PC Input Panel. The tool generates error reports and transmits them to Microsoft over a secure connection. Microsoft uses these error reports to improve handwriting recognition in future versions of Windows.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    it { should exist }
    it { should have_property 'PreventHandwritingErrorReports' }
    its('PreventHandwritingErrorReports') { should eq 1 }
  end
end

control 'windows-230' do
  title 'Ensure \'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Internet Connection Wizard can connect to Microsoft to download a list of Internet Service Providers (ISPs).

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Internet Connection Wizard') do
    it { should exist }
    it { should have_property 'ExitOnMSICW' }
    its('ExitOnMSICW') { should eq 1 }
  end
end

control 'windows-231' do
  title 'Ensure \'Turn off Internet download for Web publishing and online ordering wizards\' is set to \'Enabled\''
  desc 'This policy setting controls whether Windows will download a list of providers for the Web publishing and online ordering wizards.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should eq 1 }
  end
end

control 'windows-232' do
  title 'Ensure \'Turn off printing over HTTP\' is set to \'Enabled\''
  desc 'This policy setting allows you to disable the client computer\'s ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should exist }
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should eq 1 }
  end
end

control 'windows-233' do
  title 'Ensure \'Turn off Registration if URL connection is referring to Microsoft.com\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Windows Registration Wizard connects to Microsoft.com for online registration.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.7'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Registration Wizard Control') do
    it { should exist }
    it { should have_property 'NoRegistration' }
    its('NoRegistration') { should eq 1 }
  end
end

control 'windows-234' do
  title 'Ensure \'Turn off Search Companion content file updates\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Search Companion should automatically download content updates during local and Internet searches.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.8'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SearchCompanion') do
    it { should exist }
    it { should have_property 'DisableContentFileUpdates' }
    its('DisableContentFileUpdates') { should eq 1 }
  end
end

control 'windows-235' do
  title 'Ensure \'Turn off the \'Order Prints\' picture task\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the \'Order Prints Online\' task is available from Picture Tasks in Windows folders.

  The Order Prints Online Wizard is used to download a list of providers and allow users to order prints online.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.9'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoOnlinePrintsWizard' }
    its('NoOnlinePrintsWizard') { should eq 1 }
  end
end

control 'windows-236' do
  title 'Ensure \'Turn off the \'Publish to Web\' task for files and folders\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the tasks Publish this file to the Web, Publish this folder to the Web, and Publish the selected items to the Web are available from File and Folder Tasks in Windows folders.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.10'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoPublishingWizard' }
    its('NoPublishingWizard') { should eq 1 }
  end
end

control 'windows-237' do
  title 'Ensure \'Turn off the Windows Messenger Customer Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Windows Messenger can collect anonymous information about how the Windows Messenger software and service is used. Microsoft uses information collected through the Customer Experience Improvement Program to detect software flaws so that they can be corrected more quickly, enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.11'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should exist }
    it { should have_property 'CEIP' }
    its('CEIP') { should eq 2 }
  end
end

control 'windows-238' do
  title 'Ensure \'Turn off Windows Customer Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Windows Messenger can collect anonymous information about how the Windows Messenger software and service is used.

  Microsoft uses information collected through the Windows Customer Experience Improvement Program to detect software flaws so that they can be corrected more quickly, enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose. The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.12'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows') do
    it { should exist }
    it { should have_property 'CEIPEnable' }
    its('CEIPEnable') { should eq 0 }
  end
end

control 'windows-239' do
  title 'Ensure \'Turn off Windows Error Reporting\' is set to \'Enabled\''
  desc 'This policy setting controls whether or not errors are reported to Microsoft.

  Error Reporting is used to report information about a system or application that has failed or has stopped responding and is used to improve the quality of the product.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.22.1.13'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.22.1.13'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should exist }
    it { should have_property 'Disabled' }
    its('Disabled') { should eq 1 }
  end
end

control 'windows-240' do
  title 'Ensure \'Support device authentication using certificate\' is set to \'Enabled: Automatic\''
  desc 'This policy setting allows you to set support for Kerberos to attempt authentication using the certificate for the device to the domain.

  Support for device authentication using certificate will require connectivity to a DC in the device account domain which supports certificate authentication for computer accounts.

  The recommended state for this setting is: Enabled: Automatic.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.25.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should exist }
    it { should have_property 'DevicePKInitBehavior' }
    its('DevicePKInitBehavior') { should eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should exist }
    it { should have_property 'DevicePKInitEnabled' }
    its('DevicePKInitEnabled') { should eq 1 }
  end
end

control 'windows-241' do
  title 'Ensure \'Disallow copying of user input methods to the system account for sign-in\' is set to \'Enabled\''
  desc 'This policy prevents automatic copying of user input methods to the system account for use on the sign-in screen. The user is restricted to the set of input methods that are enabled in the system account.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.26.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.26.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International') do
    it { should exist }
    it { should have_property 'BlockUserInputMethodsForSignIn' }
    its('BlockUserInputMethodsForSignIn') { should eq 1 }
  end
end

control 'windows-242' do
  title 'Ensure \'Block user from showing account details on signin\' is set to \'Enabled\''
  desc 'This policy prevents the user from showing account details (email address or user name) on the sign-in screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'BlockUserFromShowingAccountDetailsOnSignin' }
    its('BlockUserFromShowingAccountDetailsOnSignin') { should eq 1 }
  end
end

control 'windows-243' do
  title 'Ensure \'Do not enumerate connected users on domain-joined computers\' is set to \'Enabled\''
  desc 'This policy setting prevents connected users from being enumerated on domain-joined computers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should eq 1 }
  end
end

control 'windows-244' do
  title 'Ensure \'Do not enumerate connected users on domain-joined computers\' is set to \'Enabled\''
  desc 'This policy setting prevents connected users from being enumerated on domain-joined computers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DontEnumerateConnectedUsers' }
    its('DontEnumerateConnectedUsers') { should eq 1 }
  end
end

control 'windows-245' do
  title 'Ensure \'Enumerate local users on domain-joined computers\' is set to \'Disabled\' (MS only)'
  desc 'This policy setting allows local users to be enumerated on domain-joined computers.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'ms_or_dc\') is set to MS') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('ms_or_dc') == 'MS')
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnumerateLocalUsers' }
    its('EnumerateLocalUsers') { should eq 0 }
  end
end

control 'windows-246' do
  title 'Ensure \'Turn off app notifications on the lock screen\' is set to \'Enabled\''
  desc 'This policy setting allows you to prevent app notifications from appearing on the lock screen.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'DisableLockScreenAppNotifications' }
    its('DisableLockScreenAppNotifications') { should eq 1 }
  end
end

control 'windows-247' do
  title 'Ensure \'Turn off picture password sign-in\' is set to \'Enabled\''
  desc 'This policy setting allows you to control whether a domain user can sign in using a picture password.

  The recommended state for this setting is: Enabled.

  **Note:** If the picture password feature is permitted, the user\'s domain password is cached in the system vault when using it.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should eq 0 }
  end
end

control 'windows-248' do
  title 'Ensure \'Turn on convenience PIN sign-in\' is set to \'Disabled\''
  desc 'This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer Configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.

  **Note:** The user\'s domain password will be cached in the system vault when using this feature.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.27.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.27.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should eq 0 }
  end
end

control 'windows-249' do
  title 'Ensure \'Untrusted Font Blocking\' is set to \'Enabled: Block untrusted fonts and log events\''
  desc 'This security feature provides a global setting to prevent programs from loading untrusted fonts. Untrusted fonts are any font installed outside of the %windir%\Fonts directory. This feature can be configured to be in 3 modes: On, Off, and Audit.

  The recommended state for this setting is: Enabled: Block untrusted fonts and log events '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.28.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions') do
    it { should exist }
    it { should have_property 'MitigationOptions_FontBocking' }
    its('MitigationOptions_FontBocking') { should eq '1000000000000' }
  end
end

control 'windows-250' do
  title 'Ensure \'Require a password when a computer wakes (on battery)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.33.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should eq 0 }
  end
end

control 'windows-251' do
  title 'Ensure \'Require a password when a computer wakes (plugged in)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.33.6.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should exist }
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should eq 0 }
  end
end

control 'windows-252' do
  title 'Ensure \'Require a password when a computer wakes (on battery)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should eq 1 }
  end
end

control 'windows-253' do
  title 'Ensure \'Require a password when a computer wakes (plugged in)\' is set to \'Enabled\''
  desc 'Specifies whether or not the user is prompted for a password when the system resumes from sleep.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.33.6.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should exist }
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should eq 1 }
  end
end

control 'windows-254' do
  title 'Ensure \'Configure Offer Remote Assistance\' is set to \'Disabled\''
  desc 'This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.

  Help desk and support personnel will not be able to proactively offer assistance, although they can still respond to user assistance requests.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.35.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.35.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fAllowUnsolicited' }
    its('fAllowUnsolicited') { should eq 0 }
  end
end

control 'windows-255' do
  title 'Ensure \'Configure Solicited Remote Assistance\' is set to \'Disabled\''
  desc 'This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.35.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.35.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should eq 0 }
  end
end

control 'windows-256' do
  title 'Ensure \'Enable RPC Endpoint Mapper Client Authentication\' is set to \'Enabled\' (MS only)'
  desc 'This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner. This policy setting can cause a specific issue with **1-way** forest trusts if it is applied to the **trusting** domain DCs (see Microsoft [KB3073942](https://support.microsoft.com/en-us/kb/3073942)), so we do not recommend applying it to Domain Controllers.

  **Note:** This policy will not be in effect until the system is rebooted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.36.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.36.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should exist }
    it { should have_property 'EnableAuthEpResolution' }
    its('EnableAuthEpResolution') { should eq 1 }
  end
end

control 'windows-257' do
  title 'Ensure \'Restrict Unauthenticated RPC clients\' is set to \'Enabled: Authenticated\' (MS only)'
  desc 'This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.

  This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. **This policy setting should never be applied to a Domain Controller.**

  A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.

  -- **None** allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.

  -- **Authenticated** allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.

  -- **Authenticated without exceptions** allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed. **This value has the potential to cause serious problems and is not recommended.**

  **Note:** This policy setting will not be applied until the system is rebooted.

  The recommended state for this setting is: Enabled: Authenticated.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.36.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.36.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should exist }
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should eq 1 }
  end
end

control 'windows-258' do
  title 'Ensure \'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider\' is set to \'Disabled\''
  desc ' This policy setting configures Microsoft Support Diagnostic Tool (MSDT) interactive communication with the support provider. MSDT gathers diagnostic data for analysis by support professionals.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.44.5.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.44.5.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    it { should exist }
    it { should have_property 'DisableQueryRemoteServer' }
    its('DisableQueryRemoteServer') { should eq 0 }
  end
end

control 'windows-259' do
  title 'Ensure \'Enable/Disable PerfTrack\' is set to \'Disabled\''
  desc 'This policy setting specifies whether to enable or disable tracking of responsiveness events.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.44.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.44.11.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}') do
    it { should exist }
    it { should have_property 'ScenarioExecutionEnabled' }
    its('ScenarioExecutionEnabled') { should eq 0 }
  end
end

control 'windows-260' do
  title 'Ensure \'Turn off the advertising ID\' is set to \'Enabled\''
  desc 'This policy setting turns off the advertising ID, preventing apps from using the ID for experiences across apps.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.46.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.46.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\policies\\Microsoft\\Windows\\AdvertisingInfo') do
    it { should exist }
    it { should have_property 'DisabledByGroupPolicy' }
    its('DisabledByGroupPolicy') { should eq 1 }
  end
end

control 'windows-261' do
  title 'Ensure \'Enable Windows NTP Client\' is set to \'Enabled\''
  desc 'This policy setting specifies whether the Windows NTP Client is enabled. Enabling the Windows NTP Client allows your computer to synchronize its computer clock with other NTP servers. You might want to disable this service if you decide to use a third-party time provider.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.49.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.49.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient') do
    it { should exist }
    it { should have_property 'Enabled' }
    its('Enabled') { should eq 1 }
  end
end

control 'windows-262' do
  title 'Ensure \'Enable Windows NTP Server\' is set to \'Disabled\' (MS only)'
  desc 'This policy setting allows you to specify whether the Windows NTP Server is enabled.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.8.49.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.8.49.1.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpServer') do
    it { should exist }
    it { should have_property 'Enabled' }
    its('Enabled') { should eq 0 }
  end
end

control 'windows-263' do
  title 'Ensure \'Allow a Windows app to share application data between users\' is set to \'Disabled\''
  desc 'Manages a Windows app\'s ability to share data between users who have installed the app. Data is shared through the SharedLocal folder. This folder is available through the Windows.Storage API.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.4.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager') do
    it { should exist }
    it { should have_property 'AllowSharedLocalAppData' }
    its('AllowSharedLocalAppData') { should eq 0 }
  end
end

control 'windows-264' do
  title 'Ensure \'Allow Microsoft accounts to be optional\' is set to \'Enabled\''
  desc 'This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.6.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should eq 1 }
  end
end

control 'windows-265' do
  title 'Ensure \'Set the default behavior for AutoRun\' is set to \'Enabled: Do not execute any autorun commands\''
  desc 'This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.

  The recommended state for this setting is: Enabled: Do not execute any autorun commands.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should eq 1 }
  end
end

control 'windows-266' do
  title 'Ensure \'Set the default behavior for AutoRun\' is set to \'Enabled: Do not execute any autorun commands\''
  desc 'This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.

  The recommended state for this setting is: Enabled: Do not execute any autorun commands.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should eq 1 }
  end
end

control 'windows-267' do
  title 'Ensure \'Turn off Autoplay\' is set to \'Enabled: All drives\''
  desc 'Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.

  **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.

  The recommended state for this setting is: Enabled: All drives.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.8.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.8.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should eq 255 }
  end
end

control 'windows-268' do
  title 'Ensure \'Configure enhanced anti-spoofing\' is set to \'Enabled\''
  desc 'This policy setting determines whether enhanced anti-spoofing is configured for devices which support it.

  The recommended state for this setting is: Enabled. '
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.10.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures') do
    it { should exist }
    it { should have_property 'EnhancedAntiSpoofing' }
    its('EnhancedAntiSpoofing') { should eq 1 }
  end
end

control 'windows-269' do
  title 'Ensure \'Allow Use of Camera\' is set to \'Disabled\''
  desc 'This policy setting controls whether the use of Camera devices on the machine are permitted.
  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.12.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Camera') do
    it { should exist }
    it { should have_property 'AllowCamera' }
    its('AllowCamera') { should eq 0 }
  end
end

control 'windows-270' do
  title 'Ensure \'Turn off Microsoft consumer experiences\' is set to \'Enabled\''
  desc 'This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.
  The recommended state for this setting is: Enabled.

  Note: Per Microsoft TechNet, this policy setting only applies to Windows 10 Enterprise and Windows 10 Education editions.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.13.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    it { should exist }
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should eq 1 }
  end
end

control 'windows-271' do
  title 'Ensure \'Require pin for pairing\' is set to \'Enabled\''
  desc 'This policy setting controls whether or not a PIN is required for pairing to a wireless display device.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.14.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
    it { should exist }
    it { should have_property 'RequirePinForPairing' }
    its('RequirePinForPairing') { should eq 1 }
  end
end

control 'windows-272' do
  title 'Ensure \'Do not display the password reveal button\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure the display of the password reveal button in password entry user experiences.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.15.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.15.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI') do
    it { should exist }
    it { should have_property 'DisablePasswordReveal' }
    its('DisablePasswordReveal') { should eq 1 }
  end
end

control 'windows-273' do
  title 'Ensure \'Enumerate administrator accounts on elevation\' is set to \'Disabled\''
  desc 'This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.15.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.15.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should exist }
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should eq 0 }
  end
end

control 'windows-274' do
  title 'Ensure \'Allow Telemetry\' is set to \'Enabled: 0 - Security [Enterprise Only]\' or \'Enabled: 1 - Basic\''
  desc 'This policy setting determines the amount of diagnostic and usage data reported to Microsoft.

  A value of 0 will send minimal data to Microsoft. This data includes Malicious Software Removal Tool (MSRT)  Windows Defender data, if enabled, and telemetry client settings. Setting a value of 0 applies to enterprise, EDU, IoT and server devices only. Setting a value of 0 for other devices is equivalent to choosing a value of 1. A value of 1 sends only a basic amount of diagnostic and usage data. Note that setting values of 0 or 1 will degrade certain experiences on the device. A value of 2 sends enhanced diagnostic and usage data. A value of 3 sends the same data as a value of 2, plus additional diagnostics data, including the files and content that may have caused the problem. Windows 10 telemetry settings apply to the Windows operating system and some first party apps. This setting does not apply to third party apps running on Windows 10.

  The recommended state for this setting is: Enabled: 0 - Security [Enterprise Only].

  **Note:** If the \'Allow Telemetry\' setting is configured to \'0 - Security [Enterprise Only]\', then the options in Windows Update to defer upgrades and updates will have no effect.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'AllowTelemetry' }
    its('AllowTelemetry') { should eq 0 }
  end
end

control 'windows-275' do
  title 'Ensure \'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service\' is set to \'Enabled: Disable Authenticated Proxy usage\''
  desc 'This policy setting controls whether the Connected User Experience and Telemetry service can automatically use an authenticated proxy to send data back to Microsoft.
  The recommended state for this setting is: Enabled: Disable Authenticated Proxy usage.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'DisableEnterpriseAuthProxy' }
    its('DisableEnterpriseAuthProxy') { should eq 1 }
  end
end

control 'windows-276' do
  title 'Ensure \'Disable pre-release features or settings\' is set to \'Disabled\''
  desc 'This policy setting determines the level that Microsoft can experiment with the product to study user preferences or device behavior. A value of 1 permits Microsoft to configure device settings only. A value of 2 allows Microsoft to conduct full experimentations.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should exist }
    it { should have_property 'EnableConfigFlighting' }
    its('EnableConfigFlighting') { should eq 0 }
  end
end

control 'windows-277' do
  title 'Ensure \'Do not show feedback notifications\' is set to \'Enabled\''
  desc 'This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should exist }
    it { should have_property 'DoNotShowFeedbackNotifications' }
    its('DoNotShowFeedbackNotifications') { should eq 1 }
  end
end

control 'windows-278' do
  title 'Ensure \'Toggle user control over Insider builds\' is set to \'Disabled\''
  desc 'This policy setting determines whether users can access the Insider build controls in the Advanced Options for Windows Update. These controls are located under \'Get Insider builds,\' and enable users to make their devices available for downloading and installing Windows preview software.

  The recommended state for this setting is: Disabled.

  **Note:** This policy setting applies only to devices running Windows 10 Pro, Windows 10 Enterprise, or Server 2016.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.16.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should exist }
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should eq 0 }
  end
end

control 'windows-279' do
  title 'Ensure \'EMET 5.52\' or higher is installed'
  desc 'The Enhanced Mitigation Experience Toolkit (EMET) is free and supported security software developed by Microsoft that allows an enterprise to apply exploit mitigations to applications that run on Windows. Many of these mitigations were later coded directly into Windows 10 and Server 2016.

  More information on EMET, including download and User Guide, can be obtained here:
  Enhanced Mitigation Experience Toolkit - EMET - TechNet Security

  Note: Although EMET is quite effective at enhancing exploit protection on Windows server OSes prior to Server 2016, it is highly recommended that compatibility testing is done on typical server configurations (including all CIS-recommended EMET settings) before widespread deployment to your environment.

  Note #2: Microsoft has announced that EMET will be End-Of-Life (EOL) on July 31, 2018. This does not mean the software will stop working, only that Microsoft will not update it any further past that date, nor troubleshoot new problems with it. They are instead recommending that servers be upgraded to Server 2016.
  Note #3: EMET has been reported to be very problematic on 32-bit OSes - we only recommend using it with 64-bit OSes.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe package('EMET*').version do
    it { should be_installed }
    its('version') { should cmp >= '5.51' }
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\services\\EMET_Service') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should cmp == 2 }
  end
end

control 'windows-280' do
  title 'Ensure \'Default Action and Mitigation Settings\' is set to \'Enabled\' (plus subsettings)'
  desc 'This setting configures the default action after detection and advanced ROP mitigation.

  The recommended state for this setting is:
  - Default Action and Mitigation Settings - Enabled
  - Deep Hooks - Enabled
  - Anti Detours - Enabled
  - Banned Functions - Enabled
  - Exploit Action -User Configured'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'AntiDetours' }
    it { should have_property 'BannedFunctions' }
    it { should have_property 'DeepHooks' }
    it { should have_property 'ExploitAction' }
    its('AntiDetours') { should eq 1 }
    its('BannedFunctions') { should eq 1 }
    its('DeepHooks') { should eq 1 }
    its('ExploitAction') { should eq 2 }
  end
end

control 'windows-281' do
  title 'Ensure \'Default Protections for Internet Explorer\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to Internet Explorer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EMET\\Defaults\\IE') do
    it { should exist }
    it { should have_property 'AntiDetours' }
    its('AntiDetours') { should eq 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults') do
    it { should exist }
    it { should have_property 'IE' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults') do
    it { should exist }
    it { should have_property '*\\Internet Explorer\\iexplore.exe' }
    its(['*\\Internet Explorer\\iexplore.exe']) { should eq '+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2' }
  end
end

control 'windows-282' do
  title 'Ensure \'Default Protections for Popular Software\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to the following popular software:
  - 7-Zip
  - Adobe Photoshop
  - Foxit Reader
  - Google Chrome
  - Google Talk
  - iTunes
  - Microsoft Live Writer
  - Microsoft Lync Communicator
  - Microsoft Photo Gallery
  - Microsoft SkyDrive
  - mIRC
  - Mozilla Firefox
  - Mozilla Thunderbird
  - Opera
  - Pidgin
  - QuickTime Player
  - RealPlayer
  - Safari
  - Skype
  - VideoLAN VLC
  - Winamp
  - Windows Live Mail
  - Windows Media Player
  - WinRAR
  - WinZip
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe powershell('c:\\\'Program Files (x86)\'\\\'EMET 5.5\'\\EMET_Conf.exe --list') do
    its('stderr') { should eq '' }
    its('stdout') { should match(/^7z\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^7zFM\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^7zG\.exe\s+\*\\7-Zip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^chrome\.exe\s+\*\\Google\\Chrome\\Application\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^firefox\.exe\s+\*\\Mozilla Firefox\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Foxit Reader\.exe\s+\*\\Foxit Reader\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^googletalk\.exe\s+\*\\Google\\Google Talk\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^iTunes\.exe\s+\*\\iTunes\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^LYNC\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^mirc\.exe\s+\*\\mIRC\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^opera\.exe\s+\*\\Opera\\\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^opera\.exe\s+\*\\Opera\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Photoshop\.exe\s+\*\\Adobe\\Adobe Photoshop CS\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^pidgin\.exe\s+\*\\Pidgin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^plugin-container\.exe\s+\*\\Mozilla Firefox\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^plugin-container\.exe\s+\*\\Mozilla Thunderbird\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^QuickTimePlayer\.exe\s+\*\\QuickTime\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^rar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^realconverter\.exe\s+\*\\Real\\RealPlayer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^realplay\.exe\s+\*\\Real\\RealPlayer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Safari\.exe\s+\*\\Safari\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^SkyDrive\.exe\s+\*\\SkyDrive\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^Skype\.exe\s+\*\\Skype\\Phone\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^thunderbird\.exe\s+\*\\Mozilla Thunderbird\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^unrar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^vlc\.exe\s+\*\\VideoLAN\\VLC\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winamp\.exe\s+\*\\Winamp\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winrar\.exe\s+\*\\WinRAR\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winzip32\.exe\s+\*\\WinZip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^winzip64\.exe\s+\*\\WinZip\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WLXPhotoGallery\.exe\s+\*\\Windows Live\\Photo Gallery\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wmplayer\.exe\s+\*\\Windows Media Player\s+(\S+\s?){2,14}$/) }
  end
end

control 'windows-283' do
  title 'Ensure \'Default Protections for Recommended Software\' is set to \'Enabled\''
  desc 'This setting determines if recommended EMET mitigations are applied to the following software:

  * Adobe Acrobat
  * Adobe Acrobat Reader
  * Microsoft Office suite applications
  * Oracle Java
  * WordPad
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe powershell('c:\\\'Program Files (x86)\'\\\'EMET 5.5\'\\EMET_Conf.exe --list') do
    its('stderr') { should eq '' }
    its('stdout') { should match(/^Acrobat\.exe\s+\*\\Adobe\\Acrobat\*\\Acrobat\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^AcroRd32\.exe\s+\*\\Adobe\\\*\\Reader\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^communicator\.exe\s+\*\\Microsoft Lync\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^EXCEL\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^iexplore\.exe\s+\*\\Internet Explorer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^INFOPATH\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^java\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^javaw\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^javaws\.exe\s+\*\\Java\\jre\*\\bin\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^MSACCESS\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^MSPUB\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^OIS\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^OUTLOOK\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^POWERPNT\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^PPTVIEW\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^VISIO\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^VPREVIEW\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WindowsLiveWriter\.exe\s+\*\\Windows Live\\Writer\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^WINWORD\.EXE\s+\*\\OFFICE1\*\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wlmail\.exe\s+\*\\Windows Live\\Mail\s+(\S+\s?){2,14}$/) }
    its('stdout') { should match(/^wordpad\.exe\s+\*\\Windows NT\\Accessories\s+(\S+\s?){2,14}$/) }
  end
end

control 'windows-284' do
  title 'Ensure \'System ASLR\' is set to \'Enabled: Application Opt-In\''
  desc 'This setting determines how applications become enrolled in Address Space Layout Randomization (ASLR).

  The recommended state for this setting is: Enabled: Application Opt-In.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'ASLR' }
    its('AntiDetours') { should eq 3 }
  end
end

control 'windows-285' do
  title 'Ensure \'System DEP\' is set to \'Enabled: Application Opt-Out\''
  desc 'This setting determines how applications become enrolled in Data Execution Protection (DEP).

  The recommended state for this setting is: Enabled: Application Opt-Out.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'DEP' }
    its('DEP') { should cmp eq 2 }
  end
end

control 'windows-286' do
  title 'Ensure \'System SEHOP\' is set to \'Enabled: Application Opt-Out\''
  desc 'This setting determines how applications become enrolled in Structured Exception Handler Overwrite Protection (SEHOP).

  The recommended state for this setting is: Enabled: Application Opt-Out.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.24.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings') do
    it { should exist }
    it { should have_property 'SEHOP' }
    its('SEHOP') { should eq 2 }
  end
end

control 'windows-289' do
  title 'Ensure \'Application: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-290' do
  title 'Ensure \'Application: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 32,768 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-291' do
  title 'Ensure \'Security: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-292' do
  title 'Ensure \'Security: Specify the maximum log file size (KB)\' is set to \'Enabled: 196,608 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 196,608 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 196608 }
  end
end

control 'windows-293' do
  title 'Ensure \'Setup: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-294' do
  title 'Ensure \'Setup: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.

  The recommended state for this setting is: Enabled: 32,768 or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-295' do
  title 'Ensure \'System: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\''
  desc 'This policy setting controls Event Log behavior when the log file reaches its maximum size.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should exist }
    it { should have_property 'Retention' }
    its('Retention') { should eq 0 }
  end
end

control 'windows-296' do
  title 'Ensure \'System: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\''
  desc 'Diese Richtlinieneinstellung gibt die maximale Größe der Protokolldatei in Kilobyte an. Die maximale Protokolldateigröße kann zwischen 1 Megabyte (1.024 Kilobyte) und 2 Terabyte (2.147.483.647 Kilobyte) in Kilobyte-Schritten konfiguriert werden.

  Der empfohlene Status für diese Einstellung ist: Enabled: 32,768 or greater.
  Es wird hier 262,144 kB empfohlen'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.26.4.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.26.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should exist }
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32768 }
  end
end

control 'windows-297' do
  title 'Ensure \'Turn off Data Execution Prevention for Explorer\' is set to \'Disabled\''
  desc 'Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoDataExecutionPrevention' }
    its('NoDataExecutionPrevention') { should eq 0 }
  end
end

control 'windows-298' do
  title 'Ensure \'Turn off heap termination on corruption\' is set to \'Disabled\''
  desc 'Without heap termination on corruption, legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Ensuring that heap termination on corruption is active will prevent this.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should exist }
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should eq 0 }
  end
end

control 'windows-299' do
  title 'Ensure \'Turn off shell protocol protected mode\' is set to \'Disabled\''
  desc 'This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.30.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.30.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should exist }
    it { should have_property 'PreXPSP2ShellProtocolBehavior' }
    its('PreXPSP2ShellProtocolBehavior') { should eq 0 }
  end
end

control 'windows-300' do
  title 'Ensure \'Turn off Windows Location Provider\' is set to \'Enabled\''
  desc 'This policy setting turns off the Windows Location Provider feature for the computer.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.39.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012 and if attribute(\'level_1_or_2\') is set to 2') do
    ((os[:name].include? '2012') && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should exist }
    it { should have_property 'DisableWindowsLocationProvider' }
    its('DisableWindowsLocationProvider') { should eq 1 }
  end
end

control 'windows-301' do
  title 'Ensure \'Turn off location\' is set to \'Enabled\''
  desc 'This policy setting turns off the location feature for the computer.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.39.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.39.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should exist }
    it { should have_property 'DisableLocation' }
    its('DisableLocation') { should eq 1 }
  end
end

control 'windows-302' do
  title 'Ensure \'Allow Message Service Cloud Sync\' is set to \'Disabled\''
  desc 'This policy setting allows backup and restore of cellular text messages to Microsoft\'s cloud services.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.43.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
    it { should exist }
    it { should have_property 'AllowMessageSync' }
    its('AllowMessageSync') { should eq 0 }
  end
end

control 'windows-303' do
  title 'Ensure \'Block all consumer Microsoft account user authentication\' is set to \'Enabled\''
  desc 'This setting determines whether applications and services on the device can utilize new consumer Microsoft account authentication via the Windows OnlineID and WebAccountManager APIs.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.44.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount') do
    it { should exist }
    it { should have_property 'DisableUserAuth' }
    its('DisableUserAuth') { should eq 1 }
  end
end

control 'windows-304' do
  title 'Ensure \'Prevent the usage of OneDrive for file storage\' is set to \'Enabled\''
  desc 'This policy setting lets you prevent apps and features from working with files on OneDrive using the Next Generation Sync Client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.52.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.52.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should exist }
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should eq 1 }
  end
end

control 'windows-305' do
  title 'Ensure \'Prevent the usage of OneDrive for file storage on Windows 8.1\' is set to \'Enabled\''
  desc 'This policy setting lets you prevent apps and features from working with files on OneDrive using the legacy OneDrive/SkyDrive client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.52.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should exist }
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should eq 1 }
  end
end

control 'windows-306' do
  title 'Ensure \'Do not allow passwords to be saved\' is set to \'Enabled\''
  desc 'This policy setting helps prevent Remote Desktop Services / Terminal Services clients from saving passwords on a computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should eq 1 }
  end
end

control 'windows-307' do
  title 'Ensure \'Restrict Remote Desktop Services users to a single Remote Desktop Services session\' is set to \'Enabled\''
  desc 'This policy setting allows you to restrict users to a single Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fSingleSessionPerUser' }
    its('fSingleSessionPerUser') { should eq 1 }
  end
end

control 'windows-308' do
  title 'Ensure \'Do not allow COM port redirection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether to prevent the redirection of data to client COM ports from the remote computer in a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableCcm' }
    its('fDisableCcm') { should eq 1 }
  end
end

control 'windows-309' do
  title 'Ensure \'Do not allow drive redirection\' is set to \'Enabled\''
  desc ' This policy setting prevents users from sharing the local drives on their client computers to Terminal Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:

  \\\\TSClient\\
  <driveletter>$

  If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.

  The recommended state for this setting is: Enabled.</driveletter>'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should eq 1 }
  end
end

control 'windows-310' do
  title 'Ensure \'Do not allow LPT port redirection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether to prevent the redirection of data to client LPT ports during a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisableLPT' }
    its('fDisableLPT') { should eq 1 }
  end
end

control 'windows-311' do
  title 'Ensure \'Do not allow supported Plug and Play device redirection\' is set to \'Enabled\''
  desc 'This policy setting allows you to control the redirection of supported Plug and Play devices, such as Windows Portable Devices, to the remote computer in a Remote Desktop Services session.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.3.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fDisablePNPRedir' }
    its('fDisablePNPRedir') { should eq 1 }
  end
end

control 'windows-312' do
  title 'Ensure \'Always prompt for password upon connection\' is set to \'Enabled\''
  desc 'This policy setting specifies whether Terminal Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Terminal Services, even if they already provided the password in the Remote Desktop Connection client.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should eq 1 }
  end
end

control 'windows-313' do
  title 'Ensure \'Require secure RPC communication\' is set to \'Enabled\''
  desc 'This policy setting allows you to specify whether a terminal server requires secure remote procedure call (RPC) communication with all clients or allows unsecured communication.

  You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should eq 1 }
  end
end

control 'windows-314' do
  title 'Ensure \'Set client connection encryption level\' is set to \'Enabled: High Level\''
  desc 'This policy setting specifies whether to require the use of a specific encryption level to secure communications between client computers and RD Session Host servers during Remote Desktop Protocol (RDP) connections. This policy only applies when you are using native RDP encryption. However, native RDP encryption (as opposed to SSL encryption) is not recommended. This policy does not apply to SSL encryption.

  The recommended state for this setting is: Enabled: High Level.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.9.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.9.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should eq 3 }
  end
end

control 'windows-315' do
  title 'Ensure \'Set time limit for active but idle Remote Desktop Services sessions\' is set to \'Enabled: 15 minutes or less\''
  desc 'This policy setting allows you to specify the maximum amount of time that an active Remote Desktop Services session can be idle (without user input) before it is automatically disconnected.

  The recommended state for this setting is: Enabled: 15 minutes or less.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.10.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should be <= 900000 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should_not eq 0 }
  end
end

control 'windows-316' do
  title 'Ensure \'Set time limit for disconnected sessions\' is set to \'Enabled: 1 minute\''
  desc 'This policy setting allows you to configure a time limit for disconnected Remote Desktop Services sessions.

  The recommended state for this setting is: Enabled: 1 minute.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.10.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'MaxDisconnectionTime' }
    its('MaxDisconnectionTime') { should eq 60000 }
  end
end

control 'windows-317' do
  title 'Ensure \'Do not delete temp folders upon exit\' is set to \'Disabled\''
  desc 'This policy setting specifies whether Remote Desktop Services retains a user\'s per-session temporary folders at logoff.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.11.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'DeleteTempDirsOnExit' }
    its('DeleteTempDirsOnExit') { should eq 1 }
  end
end

control 'windows-318' do
  title 'Ensure \'Do not use temporary folders per session\' is set to \'Disabled\''
  desc 'By default, Remote Desktop Services creates a separate temporary folder on the RD Session Host server for each active session that a user maintains on the RD Session Host server. The temporary folder is created on the RD Session Host server in a Temp folder under the user\'s profile folder and is named with the \'sessionid.\' This temporary folder is used to store individual temporary files.

  To reclaim disk space, the temporary folder is deleted when the user logs off from a session.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.58.3.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.58.3.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should exist }
    it { should have_property 'PerSessionTempDir' }
    its('PerSessionTempDir') { should eq 1 }
  end
end

control 'windows-319' do
  title 'Ensure \'Prevent downloading of enclosures\' is set to \'Enabled\''
  desc 'This policy setting prevents the user from having enclosures (file attachments) downloaded from a feed to the user\'s computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.59.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.59.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
    it { should exist }
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should eq 1 }
  end
end

control 'windows-320' do
  title 'Ensure \'Allow Cloud Search\' is set to \'Enabled: Disable Cloud Search\''
  desc 'This policy setting allows search and Cortana to search cloud sources like OneDrive and SharePoint.

  The recommended state for this setting is: Enabled: Disable Cloud Search.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.60.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'AllowCloudSearch' }
    its('AllowCloudSearch') { should eq 0 }
  end
end

control 'windows-321' do
  title 'Ensure \'Allow indexing of encrypted files\' is set to \'Disabled\''
  desc 'This policy setting controls whether encrypted items are allowed to be indexed. When this setting is changed, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.60.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.60.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
  end
end

control 'windows-322' do
  title 'Ensure \'Set what information is shared in Search\' is set to \'Enabled: Anonymous info\''
  desc 'Various levels of information can be shared with Bing in Search, to include user information and location. Configuring this setting prevents users from selecting the level of information shared and enables the most restrictive selection.

  The recommended state for this setting is: Enabled: Anonymous info.'
  impact 0.5
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.60.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012 and if attribute(\'level_1_or_2\') is set to 2') do
    ((os[:name].include? '2012') && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should exist }
    it { should have_property 'ConnectedSearchPrivacy' }
    its('ConnectedSearchPrivacy') { should eq 3 }
  end
end

control 'windows-323' do
  title 'Ensure \'Turn off KMS Client Online AVS Validation\' is set to \'Enabled\''
  desc 'The Key Management Service (KMS) is a Microsoft license activation method that entails setting up a local server that stores the licenses. The server itself needs to connect to Microsoft to activate the KMS service, but subsequent on-network clients can activate Microsoft Windows OS and/or their Microsoft Office via the KMS server instead of connecting directly to Microsoft. This policy setting lets you opt-out of sending KMS client activation data to Microsoft automatically.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.65.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.65.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform') do
    it { should exist }
    it { should have_property 'NoGenTicket' }
    its('NoGenTicket') { should eq 1 }
  end
end

control 'windows-324' do
  title 'Ensure \'Configure local setting override for reporting to Microsoft MAPS\' is set to \'Disabled\''
  desc 'This policy setting configures a local override for the configuration to join Microsoft Active Protection Service (MAPS), which Microsoft has now renamed to \'Windows Defender Antivirus Cloud Protection Service\'. This setting can only be set by Group Policy.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should exist }
    it { should have_property 'LocalSettingOverrideSpynetReporting' }
    its('LocalSettingOverrideSpynetReporting') { should eq 0 }
  end
end

control 'windows-325' do
  title 'Ensure \'Join Microsoft MAPS\' is set to \'Disabled\''
  desc 'This policy setting allows you to join Microsoft MAPS. Microsoft MAPS is the online community that helps you choose how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new definitions and help it to protect your computer.

  Possible options are: (0x0) Disabled (default) (0x1) Basic membership (0x2) Advanced membership

  Basic membership will send basic information to Microsoft about software that has been detected including where the software came from the actions that you apply or that are applied automatically and whether the actions were successful.

  Advanced membership in addition to basic information will send more information to Microsoft about malicious software spyware and potentially unwanted software including the location of the software file names how the software operates and how it has impacted your computer.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.3.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should exist }
    it { should have_property 'SpynetReporting' }
    its('SpynetReporting') { should eq 0 }
  end
end

control 'windows-326' do
  title 'Ensure \'Turn on behavior monitoring\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure behavior monitoring for Windows Defender Antivirus.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.7.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.7.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should exist }
    it { should have_property 'DisableBehaviorMonitoring' }
    its('DisableBehaviorMonitoring') { should eq 0 }
  end
end

control 'windows-327' do
  title 'Ensure \'Configure Watson events\' is set to \'Disabled\''
  desc 'This policy setting allows you to configure whether or not Watson events are sent.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.9.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting') do
    it { should exist }
    it { should have_property 'DisableGenericRePorts' }
    its('DisableGenericRePorts') { should eq 1 }
  end
end

control 'windows-328' do
  title 'Ensure \'Scan removable drives\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether or not to scan for malicious software and unwanted software in the contents of removable drives, such as USB flash drives, when running a full scan.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.10.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should exist }
    it { should have_property 'DisableRemovableDriveScanning' }
    its('DisableRemovableDriveScanning') { should eq 0 }
  end
end

control 'windows-329' do
  title 'Ensure \'Turn on e-mail scanning\' is set to \'Enabled\''
  desc 'This policy setting allows you to configure e-mail scanning. When e-mail scanning is enabled, the engine will parse the mailbox and mail files, according to their specific format, in order to analyze the mail bodies and attachments. Several e-mail formats are currently supported, for example: pst (Outlook), dbx, mbx, mime (Outlook Express), binhex (Mac).

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.10.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should exist }
    it { should have_property 'DisableEmailScanning' }
    its('DisableEmailScanning') { should eq 0 }
  end
end

control 'windows-330' do
  title 'Ensure \'Configure Attack Surface Reduction rules\' is set to \'Enabled\''
  desc 'This policy setting controls the state for the Attack Surface Reduction (ASR) rules.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR') do
    it { should exist }
    it { should have_property 'ExploitGuard_ASR_Rules' }
    its('ExploitGuard_ASR_Rules') { should eq 1 }
  end
end

control 'windows-331' do
  title 'Ensure \'Configure Attack Surface Reduction rules: Set the state for each ASR rule\' is \'configured\''
  desc 'The recommended state for this setting is:

  75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - 1 (Block Office applications from injecting code into other processes)
  3b576869-a4ec-4529-8536-b80a7769e899 - 1 (Block Office applications from creating executable content)
  d4f940ab-401b-4efc-aadc-ad5f3c50688a - 1 (Block Office applications from creating child processes)
  92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - 1 (Block Win32 API calls from Office macro)
  5beb7efe-fd9a-4556-801d-275e5ffc04cc - 1 (Block execution of potentially obfuscated scripts)
  d3e037e1-3eb8-44c8-a917-57927947596d - 1 (Block JavaScript or VBScript from launching downloaded executable content)
  be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - 1 (Block executable content from email client and webmail)

  Note: More information on ASR rules can be found at the following link: [Use Attack surface reduction rules to prevent malware infection | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard)'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should exist }
    it { should have_property '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' }
    its('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84') { should eq 1 }
    it { should have_property '3b576869-a4ec-4529-8536-b80a7769e899' }
    its('3b576869-a4ec-4529-8536-b80a7769e899') { should eq 1 }
    it { should have_property 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' }
    its('d4f940ab-401b-4efc-aadc-ad5f3c50688a') { should eq 1 }
    it { should have_property '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' }
    its('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b') { should eq 1 }
    it { should have_property '5beb7efe-fd9a-4556-801d-275e5ffc04cc' }
    its('5beb7efe-fd9a-4556-801d-275e5ffc04cc') { should eq 1 }
    it { should have_property 'd3e037e1-3eb8-44c8-a917-57927947596d' }
    its('d3e037e1-3eb8-44c8-a917-57927947596d') { should eq 1 }
    it { should have_property 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' }
    its('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550') { should eq 1 }
  end
end

control 'windows-332' do
  title 'Ensure \'Prevent users and apps from accessing dangerous websites\' is set to \'Enabled: Block\''
  desc 'This policy setting controls Windows Defender Exploit Guard network protection.

  The recommended state for this setting is: Enabled: Block.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.13.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection') do
    it { should exist }
    it { should have_property 'EnableNetworkProtection' }
    its('EnableNetworkProtection') { should eq 1 }
  end
end

control 'windows-333' do
  title 'Ensure \'Turn off Windows Defender AntiVirus\' is set to \'Disabled\''
  desc 'This policy setting turns off Windows Defender Antivirus. If the setting is configured to Disabled, Windows Defender Antivirus runs and computers are scanned for malware and other potentially unwanted software.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.76.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.76.14'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should exist }
    it { should have_property 'DisableAntiSpyware' }
    its('DisableAntiSpyware') { should eq 0 }
  end
end

control 'windows-334' do
  title 'Ensure \'Prevent users from modifying settings\' is set to \'Enabled\''
  desc 'This policy setting prevent users from making changes to the Exploit protection settings area in the Windows Defender Security Center.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.79.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection') do
    it { should exist }
    it { should have_property 'DisallowExploitProtectionOverride' }
    its('DisallowExploitProtectionOverride') { should eq 1 }
  end
end

control 'windows-335' do
  title 'Ensure \'Configure Windows SmartScreen\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.80.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.80.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should exist }
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should eq 1 }
  end
end

control 'windows-336' do
  title 'Ensure \'Configure Default consent\' is set to \'Enabled: Always ask before sending data\''
  desc 'This setting allows you to set the default consent handling for error reports.

  The recommended state for this setting is: Enabled: Always ask before sending data.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.81.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Consent') do
    it { should exist }
    it { should have_property 'DefaultConsent' }
    its('DefaultConsent') { should eq 1 }
  end
end

control 'windows-337' do
  title 'Ensure \'Automatically send memory dumps for OS-generated error reports\' is set to \'Disabled\''
  desc 'This policy setting controls whether memory dumps in support of OS-generated error reports can be sent to Microsoft automatically. This policy does not apply to error reports generated by 3rd-party products, or additional data other than memory dumps.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.81.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2012') do
    os[:name].include? '2012'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should exist }
    it { should have_property 'AutoApproveOSDumps' }
    its('AutoApproveOSDumps') { should eq 0 }
  end
end

control 'windows-338' do
  title 'Ensure \'Allow suggested apps in Windows Ink Workspace\' is set to \'Disabled\''
  desc 'This policy setting determines whether suggested apps in Windows Ink Workspace are allowed.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.84.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    it { should exist }
    it { should have_property 'AllowSuggestedAppsInWindowsInkWorkspace' }
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should eq 0 }
  end
end

control 'windows-339' do
  title 'Ensure \'Allow Windows Ink Workspace\' is set to \'Enabled: On, but disallow access above lock\' OR \'Disabled\' but not \'Enabled: On\''
  desc 'This policy setting determines whether Windows Ink items are allowed above the lock screen.

  The recommended state for this setting is: Enabled: On, but disallow access above lock OR Disabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.84.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should exist }
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should eq 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should exist }
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should eq 0 }
    end
  end
end

control 'windows-340' do
  title 'Ensure \'Allow user control over installs\' is set to \'Disabled\''
  desc 'Permits users to change installation options that typically are available only to system administrators. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should eq 0 }
  end
end

control 'windows-341' do
  title 'Ensure \'Always install with elevated privileges\' is set to \'Disabled\''
  desc 'This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.

  **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.

  **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should eq 0 }
  end
end

control 'windows-342' do
  title 'Ensure \'Prevent Internet Explorer security prompt for Windows Installer scripts\' is set to \'Disabled\''
  desc 'This policy setting controls whether Web-based programs are allowed to install software on the computer without notifying the user.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.85.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.85.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should exist }
    it { should have_property 'SafeForScripting' }
    its('SafeForScripting') { should eq 0 }
  end
end

control 'windows-343' do
  title 'Ensure \'Sign-in last interactive user automatically after a system-initiated restart\' is set to \'Disabled\''
  desc 'This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.86.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.86.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system') do
    it { should exist }
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should eq 1 }
  end
end

control 'windows-344' do
  title 'Ensure \'Turn on PowerShell Script Block Logging\' is set to \'Disabled\''
  desc 'This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.95.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.95.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    it { should exist }
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should eq 0 }
  end
end

control 'windows-345' do
  title 'Ensure \'Turn on PowerShell Transcription\' is set to \'Disabled\''
  desc 'This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.95.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.95.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    it { should exist }
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should eq 0 }
  end
end

control 'windows-346' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should eq 0 }
  end
end

control 'windows-347' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'windows-348' do
  title 'Ensure \'Disallow Digest authentication\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should exist }
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should eq 0 }
  end
end

control 'windows-349' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should eq 0 }
  end
end

control 'windows-350' do
  title 'Ensure \'Allow remote server management through WinRM\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service automatically listens on the network for requests on the HTTP transport over the default HTTP port.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.2'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowAutoConfig' }
    its('AllowAutoConfig') { should eq 0 }
  end
end

control 'windows-351' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should eq 0 }
  end
end

control 'windows-352' do
  title 'Ensure \'Disallow WinRM from storing RunAs credentials\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.97.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.97.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should exist }
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should eq 1 }
  end
end

control 'windows-353' do
  title 'Ensure \'Allow Remote Shell Access\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage configuration of remote access to all supported shells to execute scripts and commands.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.98.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.98.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS') do
    it { should exist }
    it { should have_property 'AllowRemoteShellAccess' }
    its('AllowRemoteShellAccess') { should eq 0 }
  end
end

control 'windows-354' do
  title 'Ensure \'Manage preview builds\' is set to \'Enabled: Disable preview builds\''
  desc 'This policy setting determines whether users can access the Windows Insider Program controls in Settings -> Update and Security. These controls enable users to make their devices available for downloading and installing preview (beta) builds of Windows software.

  The recommended state for this setting is: Enabled: Disable preview builds.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'ManagePreviewBuilds' }
    its('ManagePreviewBuilds') { should eq 1 }
    it { should have_property 'ManagePreviewBuildsPolicyValue' }
    its('ManagePreviewBuildsPolicyValue') { should eq 1 }
  end
end

control 'windows-355' do
  title 'Ensure \'Select when Feature Updates are received\' is set to \'Enabled: Current Branch for Business, 180 days\''
  desc 'This policy setting determines what type of feature updates to receive, and when.

  The branch readiness level for each new Windows 10 feature update is initially considered a \'Current Branch\' (CB) release, to be used by organizations for initial deployments. Once Microsoft has verified the feature update should be considered for enterprise deployment, it will be declared a branch readiness level of \'Current Branch for Business\' (CBB).

  The recommended state for this setting is: Enabled: Current Branch for Business, 180 days.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'DeferFeatureUpdates' }
    its('DeferFeatureUpdates') { should eq 1 }
    it { should have_property 'DeferFeatureUpdatesPeriodInDays' }
    its('DeferFeatureUpdatesPeriodInDays') { should eq 180 }
    it { should have_property 'BranchReadinessLevel' }
    its('BranchReadinessLevel') { should eq 32 }
  end
end

control 'windows-356' do
  title 'Ensure \'Select when Quality Updates are received\' is set to \'Enabled: 0 days\''
  desc 'This settings controls when Quality Updates are received.

  The recommended state for this setting is: Enabled: 0 days.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should exist }
    it { should have_property 'DeferQualityUpdates' }
    its('DeferQualityUpdates') { should eq 1 }
    it { should have_property 'DeferQualityUpdatesPeriodInDays' }
    its('DeferQualityUpdatesPeriodInDays') { should eq 0 }
  end
end

control 'windows-357' do
  title 'Ensure \'Configure Automatic Updates\' is set to \'Enabled\''
  desc 'This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.

  After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:

  * 2 - Notify for download and auto install **(Notify before downloading any updates)**
  * 3 - Auto download and notify for install **(Download the updates automatically and notify when they are ready to be installed.) (Default setting)**
  * 4 - Auto download and schedule the install **(Automatically download updates and install them on the schedule specified below.))**
  * 5 - Allow local admin to choose setting **(Leave decision on above choices up to the local Administrators (Not Recommended))**
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'NoAutoUpdate' }
    its('NoAutoUpdate') { should eq 0 }
  end
end

control 'windows-358' do
  title 'Ensure \'Configure Automatic Updates: Scheduled install day\' is set to \'0 - Every day\''
  desc 'This policy setting specifies when computers in your environment will receive security updates from Windows Update or WSUS.

  The recommended state for this setting is: 0 - Every day.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'ScheduledInstallDay' }
    its('ScheduledInstallDay') { should eq 0 }
  end
end

control 'windows-359' do
  title 'Ensure \'No auto-restart with logged on users for scheduled automatic updates installations\' is set to \'Disabled\''
  desc 'This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '18.9.101.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '18.9.101.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should exist }
    it { should have_property 'NoAutoRebootWithLoggedOnUsers' }
    its('NoAutoRebootWithLoggedOnUsers') { should eq 0 }
  end
end
