title 'windows firewall with advanced policy'

control 'windows-120' do
  title 'Ensure \'Windows Firewall: Domain: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-121' do
  title 'Ensure \'Windows Firewall: Domain: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-122' do
  title 'Ensure \'Windows Firewall: Domain: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-123' do
  title 'Ensure \'Windows Firewall: Domain: Settings: Display a notification\' is set to \'No\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 1 }
  end
end

control 'windows-124' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log\''
  desc ' Use this option to specify the path and name of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log' }
  end
end

control 'windows-125' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-126' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-127' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'windows-128' do
  title 'Ensure \'Windows Firewall: Private: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-129' do
  title 'Ensure \'Windows Firewall: Private: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-130' do
  title 'Ensure \'Windows Firewall: Private: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-131' do
  title 'Ensure \'Windows Firewall: Private: Settings: Display a notification\' is set to \'No\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 1 }
  end
end

control 'windows-132' do
  title 'Ensure \'Windows Firewall: Private: Logging: Name\' is set to \'%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log\''
  desc 'This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.

  The recommended state for this setting is: Yes (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log' }
  end
end

control 'windows-133' do
  title 'Ensure \'Windows Firewall: Private: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-134' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-135' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end

control 'windows-136' do
  title 'Ensure \'Windows Firewall: Public: Firewall state\' is set to \'On (recommended)\''
  desc 'Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.

  The recommended state for this setting is: On (recommended).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should eq 1 }
  end
end

control 'windows-137' do
  title 'Ensure \'Windows Firewall: Public: Inbound connections\' is set to \'Block (default)\''
  desc 'This setting determines the behavior for inbound connections that do not match an inbound firewall rule.

  The recommended state for this setting is: Block (default).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DefaultInboundAction' }
    its('DefaultInboundAction') { should eq 1 }
  end
end

control 'windows-138' do
  title 'Ensure \'Windows Firewall: Public: Outbound connections\' is set to \'Allow (default)\''
  desc 'This setting determines the behavior for outbound connections that do not match an outbound firewall rule.

  The recommended state for this setting is: Allow (default).

  **Note:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DefaultOutboundAction' }
    its('DefaultOutboundAction') { should eq 0 }
  end
end

control 'windows-139' do
  title 'Ensure \'Windows Firewall: Public: Settings: Display a notification\' is set to \'Yes\''
  desc 'Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.

  The recommended state for this setting is: Yes.

  **Note:** When the Apply local firewall rules setting is configured to Yes, it is also recommended to also configure the Display a notification setting to Yes. Otherwise, users will not receive messages that ask if they want to unblock a restricted inbound connection.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'DisableNotifications' }
    its('DisableNotifications') { should eq 1 }
  end
end

control 'windows-140' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local firewall rules\' is set to \'No\''
  desc 'This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'AllowLocalPolicyMerge' }
    its('AllowLocalPolicyMerge') { should eq 0 }
  end
end

control 'windows-141' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local connection security rules\' is set to \'No\''
  desc 'This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.

  The recommended state for this setting is: No.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    it { should exist }
    it { should have_property 'AllowLocalIPsecPolicyMerge' }
    its('AllowLocalIPsecPolicyMerge') { should eq 0 }
  end
end

control 'windows-142' do
  title 'Ensure \'Windows Firewall: Public: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log\''
  desc 'Use this option to specify the path and name of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFilePath' }
    its('LogFilePath') { should eq '%SYSTEMROOT%\\system32\\logfiles\\firewall\\publicfw.log' }
  end
end

control 'windows-143' do
  title 'Ensure \'Windows Firewall: Public: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\''
  desc 'Use this option to specify the size limit of the file in which Windows Firewall will write its log information.

  The recommended state for this setting is: 16,384 KB or greater.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogFileSize' }
    its('LogFileSize') { should be >= 16384 }
  end
end

control 'windows-144' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log dropped packets\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogDroppedPackets' }
    its('LogDroppedPackets') { should eq 1 }
  end
end

control 'windows-145' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log successful connections\' is set to \'Yes\''
  desc 'Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.

  The recommended state for this setting is: Yes.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M9', 'Lokale Kommunikationsfilterung (CI)']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    it { should exist }
    it { should have_property 'LogSuccessfulConnections' }
    its('LogSuccessfulConnections') { should eq 1 }
  end
end
