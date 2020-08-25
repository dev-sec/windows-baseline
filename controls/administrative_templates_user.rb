title 'Administrative Templates (User)'

control 'windows-360' do
  title 'Ensure \'Enable screen saver\' is set to \'Enabled\''
  desc 'This policy setting enables/disables the use of desktop screen savers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveActive' }
      its('ScreenSaveActive') { should cmp 1 }
    end
  end
end

control 'windows-361' do
  title 'Ensure \'Force specific screen saver: Screen saver executable name\' is set to \'Enabled: scrnsave.scr\''
  desc 'This policy setting specifies the screen saver for the user\'s desktop.

  The recommended state for this setting is: Enabled: scrnsave.scr.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'SCRNSAVE.EXE' }
      its(['SCRNSAVE.EXE']) { should eq 'scrnsave.scr' }
    end
  end
end

control 'windows-362' do
  title 'Ensure \'Password protect the screen saver\' is set to \'Enabled\''
  desc 'This setting determines whether screen savers used on the computer are password protected.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaverIsSecure' }
      its('ScreenSaverIsSecure') { should cmp 1 }
    end
  end
end

control 'windows-363' do
  title 'Ensure \'Screen saver timeout\' is set to \'Enabled: 900 seconds or fewer, but not 0\''
  desc 'This setting specifies how much user idle time must elapse before the screen saver is launched.

  The recommended state for this setting is: Enabled: 900 seconds or fewer, but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.1.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.1.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveTimeOut' }
      its('ScreenSaveTimeOut') { should cmp <= 900 }
    end
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScreenSaveTimeOut' }
      its('ScreenSaveTimeOut') { should_not eq 0 }
    end
  end
end

control 'windows-364' do
  title 'Ensure \'Turn off toast notifications on the lock screen\' is set to \'Enabled\''
  desc 'This policy setting turns off toast notifications on the lock screen.

  The recommended state for this setting is Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.5.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.5.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoToastApplicationNotificationOnLockScreen' }
      its('NoToastApplicationNotificationOnLockScreen') { should eq 1 }
    end
  end
end

control 'windows-365' do
  title 'Ensure \'Turn off Help Experience Improvement Program\' is set to \'Enabled\''
  desc 'This policy setting specifies whether users can participate in the Help Experience Improvement program. The Help Experience Improvement program collects information about how customers use Windows Help so that Microsoft can improve it.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.6.5.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.6.5.1.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoImplicitFeedback' }
      its('NoImplicitFeedback') { should eq 1 }
    end
  end
end

control 'windows-366' do
  title 'Ensure \'Do not preserve zone information in file attachments\' is set to \'Disabled\''
  desc 'This policy setting allows you to manage whether Windows marks file attachments with information about their zone of origin (such as restricted, Internet, intranet, local). This requires NTFS in order to function correctly, and will fail without notice on FAT32. By not preserving the zone information, Windows cannot make proper risk assessments.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'SaveZoneInformation' }
      its('SaveZoneInformation') { should eq 2 }
    end
  end
end

control 'windows-367' do
  title 'Ensure \'Notify antivirus programs when opening attachments\' is set to \'Enabled\''
  desc 'This policy setting allows you to manage the behavior for notifying registered antivirus programs. If multiple programs are registered, they will all be notified.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ScanWithAntiVirus' }
      its('ScanWithAntiVirus') { should eq 3 }
    end
  end
end

control 'windows-368' do
  title 'Ensure \'Configure Windows spotlight on Lock Screen\' is set to Disabled\''
  desc 'This policy setting lets you configure Windows Spotlight on the lock screen.

  The recommended state for this setting is: Disabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'ConfigureWindowsSpotlight' }
      its('ConfigureWindowsSpotlight') { should eq 2 }
    end
  end
end

control 'windows-369' do
  title 'Ensure \'Do not suggest third-party content in Windows spotlight\' is set to \'Enabled\''
  desc 'This policy setting determines whether Windows will suggest apps and content from third-party software publishers.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019') do
    ((os[:name].include? '2016') || (os[:name].include? '2019'))
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableThirdPartySuggestions' }
      its('DisableThirdPartySuggestions') { should eq 1 }
    end
  end
end

control 'windows-370' do
  title 'Ensure \'Do not use diagnostic data for tailored experiences\' is set to \'Enabled\''
  desc 'This setting determines if Windows can use diagnostic data to provide tailored experiences to the user.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.3'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableWindowsSpotlightFeatures' }
      its('DisableWindowsSpotlightFeatures') { should eq 1 }
    end
  end
end

control 'windows-371' do
  title 'Ensure \'Turn off all Windows spotlight features\' is set to \'Enabled\''
  desc 'This policy setting lets you turn off all Windows Spotlight features at once.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.7.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'level_1_or_2\') is set to 2') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('level_1_or_2') == 2)
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\CloudContent' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'DisableWindowsSpotlightFeatures' }
      its('DisableWindowsSpotlightFeatures') { should eq 1 }
    end
  end
end

control 'windows-372' do
  title 'Ensure \'Prevent users from sharing files within their profile.\' is set to \'Enabled\''
  desc 'This policy setting specifies whether users can share files within their profile. By default users are allowed to share files within their profile to other users on their network after an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.26.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.26.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'NoInplaceSharing' }
      its('NoInplaceSharing') { should eq 1 }
    end
  end
end

control 'windows-373' do
  title 'Ensure \'Always install with elevated privileges\' is set to \'Disabled\''
  desc 'This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.

  **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.

  **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.40.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.40.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\Windows\\Installer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'AlwaysInstallElevated' }
      its('AlwaysInstallElevated') { should eq 0 }
    end
  end
end

control 'windows-374' do
  title 'Ensure \'Prevent Codec Download\' is set to \'Enabled\''
  desc 'This setting controls whether Windows Media Player is allowed to download additional codecs for decoding media files it does not already understand.

  The recommended state for this setting is: Enabled.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '19.7.44.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '19.7.44.2.1'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  registry_key(hive: 'HKEY_USERS').children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + '\\Software\\Policies\\Microsoft\\WindowsMediaPlayer' }.each do |entry|
    describe registry_key(entry) do
      it { should exist }
      it { should have_property 'PreventCodecDownload' }
      its('PreventCodecDownload') { should eq 1 }
    end
  end
end
