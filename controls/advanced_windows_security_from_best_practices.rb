title 'advanced windows security from best practices'

# control 'windows-base-100' do
#   impact 1.0
#   title 'Enable Strong Encryption for Windows Network Sessions on Clients'
#   desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions. In a homogenous Windows environment, all of the options should be enabled and testing should be performed in a heterogeneous environment to determine the maximum-security level that provides reliable functionality.'
#   describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
#     it { should exist }
#     its('NtlmMinClientSec') { should eq 537_395_200 }
#   end
# end

# control 'windows-base-101' do
#   impact 1.0
#   title 'Enable Strong Encryption for Windows Network Sessions on Servers'
#   desc 'Windows has implemented a variety of security support providers for use with RPC sessions. In a homogenous Windows environment, all of the options should be enabled and testing should be performed in a heterogeneous environment to determine the maximum-security level that provides reliable functionality.'
#   describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
#     it { should exist }
#     its('NtlmMinServerSec') { should eq 537_395_200 }
#   end
# end

control 'windows-ie-101' do
  impact 1.0
  title 'IE 64-bit tab'
  desc 'This policy setting determines whether Internet Explorer 11 uses 64-bit processes (for greater security) or 32-bit processes (for greater compatibility) when running in Enhanced Protected Mode on 64-bit versions of Windows.Important: Some ActiveX controls and toolbars may not be available when 64-bit processes are used. If you enable this policy setting, Internet Explorer 11 will use 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you disable this policy setting, Internet Explorer 11 will use 32-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you don\'t configure this policy setting, users can turn this feature on or off using Internet Explorer settings. This feature is turned off by default.'
  describe registry_key('HKLM\Software\Policies\Microsoft\Internet Explorer\Main') do
    it { should exist }
    its('Isolation64Bit') { should eq 1 }
  end
end

control 'windows-ie-102' do
  impact 1.0
  title 'Run antimalware programs against ActiveX controls'
  desc 'Active X controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone. This policy setting allows you to manage whether users may download signed ActiveX controls from a page in the zone. If you enable this policy, users can download signed controls without user intervention. If you select Prompt in the drop-down box, users are queried whether to download controls signed by untrusted publishers. Code signed by trusted publishers is silently downloaded. If you disable the policy setting, signed controls cannot be downloaded.'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3') do
    it { should exist }
    its('270C') { should eq 0 }
  end
end

control 'microsoft-online-accounts' do
  impact 1.0
  title 'Microsoft Online Accounts'
  desc 'Disabling Microsoft account logon sign-in option, eg. logging in without having to use local credentials and using microsoft online accounts'
  ref 'Block Microsoft Accounts', url: 'https://technet.microsoft.com/en-us/library/jj966262(v=ws.11).aspx'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount') do
    it { should exist }
    its('value') { should eq 0 }
  end
end

control 'disable-windows-store' do
  impact 1.0
  title 'Disable Windows Store'
  desc 'Ensure Turn off Automatic Download and Install ofupdates is set to Disabled'
  tag cis: '18.9.61.1'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore') do
    it { should exist }
    its('AutoDownload') { should eq 4 }
    its('DisableOSUpgrade') { should eq 1 }
  end
end

control 'windows-ms-technet-101' do
  title 'Ensure to disable AJRouter services'
  desc 'Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AJRouter is not installed.') do
    service('AJRouter').installed?
  end
  describe service('AJRouter') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-102' do
  title 'Ensure to disable ALG Service'
  desc 'Provides support for third-party protocol plug-ins for Internet Connection Sharing'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ALG is not installed.') do
    service('ALG').installed?
  end
  describe service('ALG') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-103' do
  title 'Ensure to disable AppMgmt service'
  desc 'Processes installation, removal, and enumeration requests for software deployed through Group Policy. If the service is disabled, users will be unable to install, remove, or enumerate software deployed through Group Policy. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AppMgmt is not installed.') do
    service('AppMgmt').installed?
  end
  describe service('AppMgmt') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-104' do
  title 'Ensure to disable AudioEndpointBuilder service'
  desc 'Manages audio devices for the Windows Audio service. If this service is stopped, audio devices and effects will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AudioEndpointBuilder is not installed.') do
    service('AudioEndpointBuilder').installed?
  end
  describe service('AudioEndpointBuilder') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-105' do
  title 'Ensure to disable Audiosrv service'
  desc 'Manages audio for Windows-based programs. If this service is stopped, audio devices and effects will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Audiosrv is not installed.') do
    service('Audiosrv').installed?
  end
  describe service('Audiosrv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-106' do
  title 'Ensure to disable AxInstSV service'
  desc 'Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control installation based on Group Policy settings. This service is started on demand and if disabled the installation of ActiveX controls will behave according to default browser settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AxInstSV is not installed.') do
    service('AxInstSV').installed?
  end
  describe service('AxInstSV') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-107' do
  title 'Ensure to disable Bthserv service'
  desc 'The Bluetooth service supports discovery and association of remote Bluetooth devices. Stopping or disabling this service may cause already installed Bluetooth devices to fail to operate properly and prevent new devices from being discovered or associated.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Bthserv is not installed.') do
    service('Bthserv').installed?
  end
  describe service('Bthserv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-108' do
  title 'Ensure to disable DcpSvc service'
  desc 'The DCP (Data Collection and Publishing) service supports first-party apps to upload data to cloud.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DcpSvc is not installed.') do
    service('DcpSvc').installed?
  end
  describe service('DcpSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-109' do
  title 'Ensure to disable DevQueryBroker service'
  desc 'Enables apps to discover devices with a backgroud task'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DevQueryBroker is not installed.') do
    service('DevQueryBroker').installed?
  end
  describe service('DevQueryBroker') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-110' do
  title 'Ensure to disable DPS service'
  desc 'The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components. If this service is stopped, diagnostics will no longer function.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DPS is not installed.') do
    service('DPS').installed?
  end
  describe service('DPS') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-111' do
  title 'Ensure to disable DiagTrack service'
  desc 'The Connected User Experiences and Telemetry service enables features that support in-application and connected user experiences. Additionally, this service manages the event-driven collection and transmission of diagnostic and usage information (used to improve the experience and quality of the Windows Platform) when the diagnostics and usage privacy option settings are enabled under Feedback and Diagnostics.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('DiagTrack is not installed.') do
    service('DiagTrack').installed?
  end
  describe service('DiagTrack') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-112' do
  title 'Ensure to disable Dmwappushservice service'
  desc 'WAP Push Message Routing Service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Dmwappushservice is not installed.') do
    service('Dmwappushservice').installed?
  end
  describe service('Dmwappushservice') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-113' do
  title 'Ensure to disable FrameServer service'
  desc 'Enables multiple clients to access video frames from camera devices.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('FrameServer is not installed.') do
    service('FrameServer').installed?
  end
  describe service('FrameServer') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-114' do
  title 'Ensure to disable hidserv service'
  desc 'Activates and maintains the use of hot buttons on keyboards, remote controls, and other multimedia devices. It is recommended that you keep this service running.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('hidserv is not installed.') do
    service('hidserv').installed?
  end
  describe service('hidserv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-115' do
  title 'Ensure to disable Icssvc service'
  desc 'Provides the ability to share a cellular data connection with another device.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Icssvc is not installed.') do
    service('Icssvc').installed?
  end
  describe service('Icssvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-116' do
  title 'Ensure to disable lfsvc service'
  desc 'This service monitors the current location of the system and manages geofences (a geographical location with associated events). If you turn off this service, applications will be unable to use or receive notifications for geolocation or geofences.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('lfsvc is not installed.') do
    service('lfsvc').installed?
  end
  describe service('lfsvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-117' do
  title 'Ensure to disable LicenseManager service'
  desc 'Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled then content acquired through the Microsoft Store will not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('LicenseManager is not installed.') do
    service('LicenseManager').installed?
  end
  describe service('LicenseManager') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-118' do
  title 'Ensure to disable MapsBroker service'
  desc 'Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps. Disabling this service will prevent apps from accessing maps.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('MapsBroker is not installed.') do
    service('MapsBroker').installed?
  end
  describe service('MapsBroker') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-119' do
  title 'Ensure to disable NcbService service'
  desc 'Brokers connections that allow Microsoft Store Apps to receive notifications from the internet.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('NcbService is not installed.') do
    service('NcbService').installed?
  end
  describe service('NcbService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-120' do
  title 'Ensure to disable PcaSvc service'
  desc 'This service provides support for the Program Compatibility Assistant (PCA). PCA monitors programs installed and run by the user and detects known compatibility problems. If this service is stopped, PCA will not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PcaSvc is not installed.') do
    service('PcaSvc').installed?
  end
  describe service('PcaSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-121' do
  title 'Ensure to disable PhoneSvc service'
  desc 'Manages the telephony state on the device'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PhoneSvc is not installed.') do
    service('PhoneSvc').installed?
  end
  describe service('PhoneSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-122' do
  title 'Ensure to disable PrintNotify service'
  desc 'This service opens custom printer dialog boxes and handles notifications from a remote print server or a printer. If you turn off this service, you won\'t be able to see printer extensions or notifications.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('PrintNotify is not installed.') do
    service('PrintNotify').installed?
  end
  describe service('PrintNotify') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-123' do
  title 'Ensure to disable qWave service'
  desc 'Quality Windows Audio Video Experience (qWave) is a networking platform for Audio Video (AV) streaming applications on IP home networks. qWave enhances AV streaming performance and reliability by ensuring network quality-of-service (QoS) for AV applications. It provides mechanisms for admission control, run time monitoring and enforcement, application feedback, and traffic prioritization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('qWave is not installed.') do
    service('qWave').installed?
  end
  describe service('qWave') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-124' do
  title 'Ensure to disable RasAuto service'
  desc 'Creates a connection to a remote network whenever a program references a remote DNS or NetBIOS name or address.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RasAuto is not installed.') do
    service('RasAuto').installed?
  end
  describe service('RasAuto') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-125' do
  title 'Ensure to disable RasMan service'
  desc 'Manages dial-up and virtual private network (VPN) connections from this computer to the Internet or other remote networks. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RasMan is not installed.') do
    service('RasMan').installed?
  end
  describe service('RasMan') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-126' do
  title 'Ensure to disable RmSvc service'
  desc 'Radio Management and Airplane Mode Service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RmSvc is not installed.') do
    service('RmSvc').installed?
  end
  describe service('RmSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-127' do
  title 'Ensure to disable RpcLocator service'
  desc 'In Windows 2003 and earlier versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and later versions of Windows, this service does not provide any functionality and is present for application compatibility.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RpcLocator is not installed.') do
    service('RpcLocator').installed?
  end
  describe service('RpcLocator') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-128' do
  title 'Ensure to disable RSoPProv service'
  desc 'Provides a network service that processes requests to simulate application of Group Policy settings for a target user or computer in various situations and computes the Resultant Set of Policy settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('RSoPProv is not installed.') do
    service('RSoPProv').installed?
  end
  describe service('RSoPProv') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-129' do
  title 'Ensure to disable Sacsvr service'
  desc 'Allows administrators to remotely access a command prompt using Emergency Management Services.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('Sacsvr is not installed.') do
    service('Sacsvr').installed?
  end
  describe service('Sacsvr') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-130' do
  title 'Ensure to disable ScDeviceEnum service'
  desc 'Creates software device nodes for all smart card readers accessible to a given session. If this service is disabled, WinRT APIs will not be able to enumerate smart card readers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ScDeviceEnum is not installed.') do
    service('ScDeviceEnum').installed?
  end
  describe service('ScDeviceEnum') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-131' do
  title 'Ensure to disable SCPolicySvc service'
  desc 'Allows the system to be configured to lock the user desktop upon smart card removal.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SCPolicySvc is not installed.') do
    service('SCPolicySvc').installed?
  end
  describe service('SCPolicySvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-132' do
  title 'Ensure to disable SensorDataService service'
  desc 'Delivers data from a variety of sensors'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensorDataService is not installed.') do
    service('SensorDataService').installed?
  end
  describe service('SensorDataService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-133' do
  title 'Ensure to disable SensorService service'
  desc 'A service for sensors that manages different sensors\' functionality. Manages Simple Device Orientation (SDO) and History for sensors. Loads the SDO sensor that reports device orientation changes. If this service is stopped or disabled, the SDO sensor will not be loaded and so auto-rotation will not occur. History collection from Sensors will also be stopped.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensorService is not installed.') do
    service('SensorService').installed?
  end
  describe service('SensorService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-134' do
  title 'Ensure to disable SensrSvc service'
  desc 'Monitors various sensors in order to expose data and adapt to system and user state. If this service is stopped or disabled, the display brightness will not adapt to lighting conditions. Stopping this service may affect other system functionality and features as well.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SensrSvc is not installed.') do
    service('SensrSvc').installed?
  end
  describe service('SensrSvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-135' do
  title 'Ensure to disable SharedAccess service'
  desc 'Provides network address translation, addressing, name resolution and/or intrusion prevention services for a home or small office network.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SharedAccess is not installed.') do
    service('SharedAccess').installed?
  end
  describe service('SharedAccess') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-136' do
  title 'Ensure to disable ShellHWDetection service'
  desc 'Provides notifications for AutoPlay hardware events.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ShellHWDetection is not installed.') do
    service('ShellHWDetection').installed?
  end
  describe service('ShellHWDetection') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-137' do
  title 'Ensure to disable SSDPSRV service'
  desc 'Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices. Also announces SSDP devices and services running on the local computer. If this service is stopped, SSDP-based devices will not be discovered. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SSDPSRV is not installed.') do
    service('SSDPSRV').installed?
  end
  describe service('SSDPSRV') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-138' do
  title 'Ensure to disable stisvc service'
  desc 'Provides image acquisition services for scanners and cameras'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('stisvc is not installed.') do
    service('stisvc').installed?
  end
  describe service('stisvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-139' do
  title 'Ensure to disable TabletInputService service'
  desc 'Enables Touch Keyboard and Handwriting Panel pen and ink functionality'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('TabletInputService is not installed.') do
    service('TabletInputService').installed?
  end
  describe service('TabletInputService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-140' do
  title 'Ensure to disable upnphost service'
  desc 'Allows UPnP devices to be hosted on this computer. If this service is stopped, any hosted UPnP devices will stop functioning and no additional hosted devices can be added. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('upnphost is not installed.') do
    service('upnphost').installed?
  end
  describe service('upnphost') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-141' do
  title 'Ensure to disable WalletService service'
  desc 'Hosts objects used by clients of the wallet'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WalletService is not installed.') do
    service('WalletService').installed?
  end
  describe service('WalletService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-142' do
  title 'Ensure to disable WbioSrvc service'
  desc 'The Windows biometric service gives client applications the ability to capture, compare, manipulate, and store biometric data without gaining direct access to any biometric hardware or samples. The service is hosted in a privileged SVCHOST process.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WbioSrvc is not installed.') do
    service('WbioSrvc').installed?
  end
  describe service('WbioSrvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-143' do
  title 'Ensure to disable wercplsupport service'
  desc 'This service provides support for viewing, sending and deletion of system-level problem reports for the Problem Reports and Solutions control panel.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wercplsupport is not installed.') do
    service('wercplsupport').installed?
  end
  describe service('wercplsupport') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-144' do
  title 'Ensure to disable WiaRpc service'
  desc 'Launches applications associated with still image acquisition events.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WiaRpc is not installed.') do
    service('WiaRpc').installed?
  end
  describe service('WiaRpc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-145' do
  title 'Ensure to disable wisvc service'
  desc 'Ensure to disable Windows Insider Service service'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wisvc is not installed.') do
    service('wisvc').installed?
  end
  describe service('wisvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-146' do
  title 'Ensure to disable wlidsvc service'
  desc 'Enables user sign-in through Microsoft account identity services. If this service is stopped, users will not be able to log on to the computer with their Microsoft account.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('wlidsvc is not installed.') do
    service('wlidsvc').installed?
  end
  describe service('wlidsvc') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-147' do
  title 'Ensure to disable WPDBusEnum service'
  desc 'Enforces group policy for removable mass-storage devices. Enables applications such as Windows Media Player and Image Import Wizard to transfer and synchronize content using removable mass-storage devices.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WPDBusEnum is not installed.') do
    service('WPDBusEnum').installed?
  end
  describe service('WPDBusEnum') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-148' do
  title 'Ensure to disable WpnService service'
  desc 'This service runs in session 0 and hosts the notification platform and connection provider which handles the connection between the device and WNS server.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('WpnService is not installed.') do
    service('WpnService').installed?
  end
  describe service('WpnService') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-149' do
  title 'Ensure to disable XblAuthManager service'
  desc 'Provides authentication and authorization services for interacting with Xbox Live. If this service is stopped, some applications may not operate correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('XblAuthManager is not installed.') do
    service('XblAuthManager').installed?
  end
  describe service('XblAuthManager') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-150' do
  title 'Ensure to disable XblGameSave service'
  desc 'This service syncs save data for Xbox Live save enabled games. If this service is stopped, game save data will not upload to or download from Xbox Live.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('XblGameSave is not installed.') do
    service('XblGameSave').installed?
  end
  describe service('XblGameSave') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-152' do
  title 'Ensure to disable AppXSVC service'
  desc 'Provides infrastructure support for deploying Store applications. This service is started on demand and if disabled Store applications will not be deployed to the system, and may not function properly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('AppXSVC is not installed.') do
    service('AppXSVC').installed?
  end
  describe service('AppXSVC') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-153' do
  title 'Ensure to disable BrokerInfrastructure service'
  desc 'Windows infrastructure service that controls which background tasks can run on the system.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('BrokerInfrastructure is not installed.') do
    service('BrokerInfrastructure').installed?
  end
  describe service('BrokerInfrastructure') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-154' do
  title 'Ensure to disable ClipSVC service'
  desc 'Provides infrastructure support for the Microsoft Store. This service is started on demand and if disabled applications bought using Microsoft Store will not behave correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('ClipSVC is not installed.') do
    service('ClipSVC').installed?
  end
  describe service('ClipSVC') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-155' do
  title 'Ensure to disable SNMPTRAP service'
  desc 'Receives trap messages generated by local or remote Simple Network Management Protocol (SNMP) agents and forwards the messages to SNMP management programs running on this computer. If this service is stopped, SNMP-based programs on this computer will not receive SNMP trap messages. If this service is disabled, any services that explicitly depend on it will fail to start.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  only_if('SNMPTRAP is not installed.') do
    service('SNMPTRAP').installed?
  end
  describe service('SNMPTRAP') do
    it { should be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control 'windows-ms-technet-156' do
  title 'Ensure to disable OneSyncSvc service'
  desc 'This service synchronizes mail, contacts, calendar and various other user data. Mail and other applications dependent on this functionality will not work properly when this service is not running.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('OneSyncSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\OneSyncSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-ms-technet-157' do
  title 'Ensure to disable UserDataSvc service'
  desc 'Provides apps access to structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('UserDataSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\UserDataSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end

control 'windows-ms-technet-158' do
  title 'Ensure to disable UnistoreSvc service'
  desc 'Handles storage of structured user data, including contact info, calendars, messages, and other content. If you stop or disable this service, apps that use this data might not work correctly.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'microsoft': 'technet'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Microsoft', url: 'https://docs.microsoft.com/de-de/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'
  ref 'Github', url: 'https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server.md'
  describe registry_key('UnistoreSvc', 'HKEY_LOCAL_MACHINE\\SYSTEM\CurrentControlSet\Services\UnistoreSvc') do
    it { should exist }
    it { should have_property 'Start' }
    its('Start') { should eq 4 }
  end
end
