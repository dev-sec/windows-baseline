title 'local policies'

control 'windows-010' do
  title 'Ensure \'Access Credential Manager as a trusted caller\' is set to \'No One\''
  desc 'This security setting is used by Credential Manager during Backup and Restore. No accounts should have this user right, as it is only assigned to Winlogon. Users\' saved credentials might be compromised if this user right is assigned to other entities.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

control 'windows-011' do
  title 'Configure \'Access this computer from the network\''
  desc 'This policy setting allows other users on the network to connect to the computer and is required by various network protocols that include Server Message Block (SMB)-based protocols, NetBIOS, Common Internet File System (CIFS), and Component Object Model Plus (COM+).

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, Authenticated Users. '
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.2', '2.2.3']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeNetworkLogonRight') { should eq attribute('se_network_logon_right') }
  end
end

control 'windows-012' do
  title 'Ensure \'Act as part of the operating system\' is set to \'No One\''
  desc 'This policy setting allows a process to assume the identity of any user and thus gain access to the resources that the user is authorized to access.
  The recommended state for this setting is: No One.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

control 'windows-013' do
  title 'Ensure \'Add workstations to domain\' is set to \'Administrators\''
  desc 'This policy setting specifies which users can add computer workstations to the domain. For this policy setting to take effect, it must be assigned to the user as part of the Default Domain Controller Policy for the domain. A user who has been assigned this right can add up to 10 workstations to the domain. Users who have been assigned the Create Computer Objects permission for an OU or the Computers container in Active Directory can add an unlimited number of computers to the domain, regardless of whether or not they have been assigned the Add workstations to domain user right.

  In Windows-based networks, the term security principal is defined as a user, group, or computer that is automatically assigned a security identifier to control access to resources. In an Active Directory domain, each computer account is a full security principal with the ability to authenticate and access domain resources. However, some organizations may want to limit the number of computers in an Active Directory environment so that they can consistently track, build, and manage the computers. If users are allowed to add computers to the domain, tracking and management efforts would be hampered. Also, users could perform activities that are more difficult to trace because of their ability to create additional unauthorized domain computers.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-014' do
  title 'Ensure \'Adjust memory quotas for a process\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting allows a user to adjust the maximum amount of memory that is available to a process. The ability to adjust memory quotas is useful for system tuning, but it can be abused. In the wrong hands, it could be used to launch a denial of service (DoS) attack.

  The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE.

  Note: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #2: A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544'] }
  end
end

control 'windows-015' do
  title 'Ensure \'Allow log on locally\' is set to \'Administrators\''
  desc 'This policy setting determines which users can interactively log on to computers in your environment. Logons that are initiated by pressing the CTRL+ALT+DEL key sequence on the client computer keyboard require this user right. Users who attempt to log on through Terminal Services / Remote Desktop Services or IIS also require this user right.

  The Guest account is assigned this user right by default. Although this account is disabled by default, it is recommended that you enable this setting through Group Policy. However, this user right should generally be restricted to the Administrators and Users groups. Assign this user right to the Backup Operators group if your organization requires that they have this capability.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeInteractiveLogonRight') { should eq attribute('se_interactive_logon_right') }
  end
end

control 'windows-016' do
  title 'Configure \'Allow log on through Remote Desktop Services\''
  desc 'This policy setting determines which users or groups have the right to log on as a Remote Desktop Services client. If your organization uses Remote Assistance as part of its help desk strategy, create a group and assign it this user right through Group Policy. If the help desk in your organization does not use Remote Assistance, assign this user right only to the Administrators group or use the Restricted Groups feature to ensure that no user accounts are part of the Remote Desktop Users group.

  Restrict this user right to the Administrators group, and possibly the Remote Desktop Users group, to prevent unwanted users from gaining access to computers on your network by means of the Remote Assistance feature.
  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, Remote Desktop Users.

  Note: A Member Server that holds the Remote Desktop Services Role with Remote Desktop Connection Broker Role Service will require a special exception to this recommendation, to allow the Authenticated Users group to be granted this user right.

  Note #2: The above lists are to be treated as whitelists, which implies that the above principals need not be present for assessment of this recommendation to pass.

  Note #3: In all versions of Windows Server prior to Server 2008 R2, Remote Desktop Services was known as Terminal Services, so you should substitute the older term if comparing against an older OS.
  '
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.8', '2.2.9']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should eq attribute('se_remote_interactive_logon_right') }
  end
end

control 'windows-017' do
  title 'Ensure \'Back up files and directories\' is set to \'Administrators\''
  desc 'This policy setting allows users to circumvent file and directory permissions to back up the system. This user right is enabled only when an application (such as NTBACKUP) attempts to access a file or directory through the NTFS file system backup application programming interface (API). Otherwise, the assigned file and directory permissions apply.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeBackupPrivilege') { should eq attribute('se_backup_privilege') }
  end
end

control 'windows-018' do
  title 'Ensure \'Change the system time\' is set to \'Administrators, LOCAL SERVICE\''
  desc 'This policy setting determines which users and groups can change the time and date on the internal clock of the computers in your environment. Users who are assigned this user right can affect the appearance of event logs. When a computer\'s time setting is changed, logged events reflect the new time, not the actual time that the events occurred.

  The recommended state for this setting is: Administrators, LOCAL SERVICE.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.11'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemtimePrivilege') { should eq attribute('se_systemtime_privilege') }
  end
end

control 'windows-019' do
  title 'Ensure \'Change the time zone\' is set to \'Administrators, LOCAL SERVICE\''
  desc 'This setting determines which users can change the time zone of the computer. This ability holds no great danger for the computer and may be useful for mobile workers.

  The recommended state for this setting is: Administrators, LOCAL SERVICE.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemtimePrivilege') { should eq attribute('se_time_zone_privilege') }
  end
end

control 'windows-020' do
  title 'Ensure \'Create a pagefile\' is set to \'Administrators\''
  desc 'This policy setting allows users to change the size of the pagefile. By making the pagefile extremely large or extremely small, an attacker could easily affect the performance of a compromised computer.
  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.13'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-021' do
  title 'Ensure \'Create a token object\' is set to \'No One\''
  desc 'This policy setting allows a process to create an access token, which may provide elevated rights to access sensitive data.
  The recommended state for this setting is: No One.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.12'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.14'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

control 'windows-022' do
  title 'Ensure \'Create global objects\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\''
  desc 'This policy setting determines whether users can create global objects that are available to all sessions. Users can still create objects that are specific to their own session if they do not have this user right.

  Users who can create global objects could affect processes that run under other users\' sessions. This capability could lead to a variety of problems, such as application failure or data corruption.

  The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.

  Note: A Member Server with Microsoft SQL Server and its optional "Integration Services" component installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.13'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.15'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
  end
end

control 'windows-023' do
  title 'Ensure \'Create permanent shared objects\' is set to \'No One\''
  desc 'This user right is useful to kernel-mode components that extend the object namespace. However, components that run in kernel mode have this user right inherently. Therefore, it is typically not necessary to specifically assign this user right.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.14'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.16'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end

control 'windows-024' do
  title 'Ensure \'Create symbolic links\' is set to \'Administrators\''
  desc 'This policy setting determines which users can create symbolic links. In Windows Vista, existing NTFS file system objects, such as files and folders, can be accessed by referring to a new kind of file system object called a symbolic link. A symbolic link is a pointer (much like a shortcut or .lnk file) to another file system object, which can be a file, folder, shortcut or another symbolic link. The difference between a shortcut and a symbolic link is that a shortcut only works from within the Windows shell. To other programs and applications, shortcuts are just another file, whereas with symbolic links, the concept of a shortcut is implemented as a feature of the NTFS file system.

  Symbolic links can potentially expose security vulnerabilities in applications that are not designed to use them. For this reason, the privilege for creating symbolic links should only be assigned to trusted users. By default, only Administrators can create symbolic links.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators and (when the Hyper-V Role is installed) NT VIRTUAL MACHINE\Virtual Machines.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.15'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.17', '2.2.18']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should eq attribute('se_create_symbolic_link_privilege') }
  end
end

control 'windows-025' do
  title 'Ensure \'Debug programs\' is set to \'Administrators\''
  desc 'This policy setting determines which user accounts will have the right to attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components. Developers who are debugging their own applications do not need to be assigned this user right; however, developers who are debugging new system components will need it.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.16'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.19'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-026' do
  title 'Ensure \'Deny access to this computer from the network\' is set to \'Guests\''
  desc 'This policy setting prohibits users from connecting to a computer from across the network, which would allow users to access and potentially modify data remotely. In high security environments, there should be no need for remote users to access data on a computer. Instead, file sharing should be accomplished through the use of network servers. This user right supersedes the Access this computer from the network user right if an account is subject to both policies.

  - Level 1 - Domain Controller. The recommended state for this setting is to include: Guests.
  - Level 1 - Member Server. The recommended state for this setting is to include: Guests, Local account and member of Administrators group.

  Caution: Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.

  Note: The security identifier Local account and member of Administrators group is not available in Server 2008 R2 and Server 2012 (non-R2) unless MSKB 2871997 has been installed.

  Note #2: Configuring a Member Server or standalone server as described above may adversely affect applications that create a local service account and place it in the Administrators group - in which case you must either convert the application to use a domain-hosted service account, or remove Local account and member of Administrators group from this User Right Assignment. Using a domain-hosted service account is strongly preferred over making an exception to this rule, where possible.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.17'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.20', '2.2.21']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should eq attribute('se_deny_network_logon_right') }
  end
end

control 'windows-027' do
  title 'Ensure \'Deny log on as a batch job\' to include \'Guests\''
  desc 'This policy setting determines which accounts will not be able to log on to the computer as a batch job. A batch job is not a batch (.bat) file, but rather a batch-queue facility. Accounts that use the Task Scheduler to schedule jobs need this user right.

  This user right supersedes the Log on as a batch job user right, which could be used to allow accounts to schedule jobs that consume excessive system resources. Such an occurrence could cause a DoS condition. Failure to assign this user right to the recommended accounts can be a security risk.

  The recommended state for this setting is to include: Guests.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.18'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.22'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-028' do
  title 'Ensure \'Deny log on as a service\' to include \'Guests\''
  desc 'This security setting determines which service accounts are prevented from registering a process as a service. This user right supersedes the Log on as a service user right if an account is subject to both policies.

  The recommended state for this setting is to include: Guests.

  Note: This security setting does not apply to the System, Local Service, or Network Service accounts.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.19'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.23'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-029' do
  title 'Ensure \'Deny log on locally\' to include \'Guests\''
  desc 'This security setting determines which users are prevented from logging on at the computer. This policy setting supersedes the Allow log on locally policy setting if an account is subject to both policies.

  The recommended state for this setting is to include: Guests.

  Important: If you apply this security policy to the Everyone group, no one will be able to log on locally.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.20'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.24'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

control 'windows-030' do
  title 'Configure \'Deny log on through Remote Desktop Services\''
  desc 'This policy setting determines whether users can log on as Remote Desktop clients. After the baseline Member Server is joined to a domain environment, there is no need to use local accounts to access the server from the network. Domain accounts can access the server for administration and end-user processing. This user right supersedes the Allow log on through Remote Desktop Services user right if an account is subject to both policies.

  - Level 1 - Domain Controller. The recommended state for this setting is: Guests.
  - Level 1 - Member Server. The recommended state for this setting is: Guests, Local account.

  Caution: Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.

  Note: The security identifier Local account is not available in Server 2008 R2 and Server 2012 (non-R2) unless MSKB 2871997 has been installed.

  Note #2: In all versions of Windows Server prior to Server 2008 R2, Remote Desktop Services was known as Terminal Services, so you should substitute the older term if comparing against an older OS.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.21'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.25', '2.2.26']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  attribute('se_deny_remote_interactive_logon_right').each do |entry|
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include entry }
    end
  end
end

control 'windows-031' do
  title 'Configure \'Enable computer and user accounts to be trusted for delegation\''
  desc 'This policy setting allows users to change the Trusted for Delegation setting on a computer object in Active Directory. Abuse of this privilege could allow unauthorized users to impersonate other users on the network.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators.
  - Level 1 - Member Server. The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.22'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.27', '2.2.28']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq attribute('se_enable_delegation_privilege') }
  end
end

control 'windows-032' do
  title 'Ensure \'Force shutdown from a remote system\' is set to \'Administrators\''
  desc 'This policy setting allows users to shut down Windows Vista-based and newer computers from remote locations on the network. Anyone who has been assigned this user right can cause a denial of service (DoS) condition, which would make the computer unavailable to service user requests. Therefore, it is recommended that only highly trusted administrators be assigned this user right.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.23'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.29'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-033' do
  title 'Ensure \'Generate security audits\' is set to \'LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting determines which users or processes can generate audit records in the Security log.
  The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.

  Note #2: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #3: A Member Server that holds the Active Directory Federation Services Role will require a special exception to this recommendation, to allow the NT SERVICE\ADFSSrv and NT SERVICE\DRS services, as well as the associated Active Directory Federation Services service account, to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.24'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.30'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeAuditPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
  end
end

control 'windows-034' do
  title 'Configure \'Impersonate a client after authentication\''
  desc 'The policy setting allows programs that run on behalf of a user to impersonate that user (or another specified account) so that they can act on behalf of the user. If this user right is required for this kind of impersonation, an unauthorized user will not be able to convince a client to connect-for example, by remote procedure call (RPC) or named pipes-to a service that they have created to impersonate that client, which could elevate the unauthorized user\'s permissions to administrative or system levels.

  Services that are started by the Service Control Manager have the built-in Service group added by default to their access tokens. COM servers that are started by the COM infrastructure and configured to run under a specific account also have the Service group added to their access tokens. As a result, these processes are assigned this user right when they are started.

  Also, a user can impersonate an access token if any of the following conditions exist:
  - The access token that is being impersonated is for this user.
  - The user, in this logon session, logged on to the network with explicit credentials to create the access token.
  - The requested level is less than Impersonate, such as Anonymous or Identify.

  An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker\'s level of access to that of the client.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE and (when the Web Server (IIS) Role with Web Services Role Service is installed) IIS_IUSRS.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.25'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.31', '2.2.32']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeImpersonatePrivilege') { should eq attribute('se_impersonate_privilege') }
  end
end

control 'windows-035' do
  title 'Ensure \'Increase scheduling priority\' is set to \'Administrators\''
  desc 'This policy setting determines whether users can increase the base priority class of a process. (It is not a privileged operation to increase relative priority within a priority class.) This user right is not required by administrative tools that are supplied with the operating system but might be required by software development tools.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.26'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.33'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-036' do
  title 'Ensure \'Load and unload device drivers\' is set to \'Administrators\''
  desc 'This policy setting allows users to dynamically load a new device driver on a system. An attacker could potentially use this capability to install malicious code that appears to be a device driver. This user right is required for users to add local printers or printer drivers in Windows Vista.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.27'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.34'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeLoadDriverPrivilege') { should eq attribute('se_load_driver_privilege') }
  end
end

control 'windows-037' do
  title 'Ensure \'Lock pages in memory\' is set to \'No One\''
  desc 'This policy setting allows a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk. If this user right is assigned, significant degradation of system performance can occur.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.28'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.35'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

control 'windows-038' do
  title 'Ensure \'Log on as a batch job\' is set to \'Administrators\' (DC only)'
  desc 'This policy setting allows accounts to log on using the task scheduler service. Because the task scheduler is often used for administrative purposes, it may be needed in enterprise environments. However, its use should be restricted in high security environments to prevent misuse of system resources or to prevent attackers from using the right to launch malicious code after gaining user level access to a computer.

  The recommended state for this setting is: Administrators.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.29'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.36'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to DC') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'DC'))
  end
  describe security_policy do
    its('SeBatchLogonRight') { should eq attribute('se_batch_logon_right') }
  end
end

control 'windows-039' do
  title 'Configure \'Manage auditing and security log\''
  desc 'This policy setting determines which users can change the auditing options for files and directories and clear the Security log.

  For environments running Microsoft Exchange Server, the Exchange Servers group must possess this privilege on Domain Controllers to properly function. Given this, DCs that grant the Exchange Servers group this privilege also conform to this benchmark. If the environment does not use Microsoft Exchange Server, then this privilege should be limited to only Administrators on DCs.

  - Level 1 - Domain Controller. The recommended state for this setting is: Administrators and (when Exchange is running in the environment) Exchange Servers.
  - Level 1 - Member Server. The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.30'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.38'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSecurityPrivilege') { should eq attribute('se_security_privilege') }
  end
end

control 'windows-040' do
  title 'Ensure \'Modify an object label\' is set to \'No One\''
  desc 'This privilege determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users. Processes running under a user account can modify the label of an object owned by that user to a lower level without this privilege.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.31'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.39'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRelabelPrivilege') { should eq [] }
  end
end

control 'windows-041' do
  title 'Ensure \'Modify firmware environment values\' is set to \'Administrators\''
  desc 'This policy setting allows users to configure the system-wide environment variables that affect hardware configuration. This information is typically stored in the Last Known Good Configuration. Modification of these values and could lead to a hardware failure that would result in a denial of service condition.
  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.32'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.40'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-042' do
  title 'Ensure \'Perform volume maintenance tasks\' is set to \'Administrators\''
  desc 'This policy setting allows users to manage the system\'s volume or disk configuration, which could allow a user to delete a volume and cause data loss as well as a denial-ofservice condition.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.33'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.41'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-043' do
  title 'Ensure \'Profile single process\' is set to \'Administrators\''
  desc 'This policy setting determines which users can use tools to monitor the performance of non-system processes. Typically, you do not need to configure this user right to use the Microsoft Management Console (MMC) Performance snap-in. However, you do need this user right if System Monitor is configured to collect data using Windows Management Instrumentation (WMI). Restricting the Profile single process user right prevents intruders from gaining additional information that could be used to mount an attack on the system.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.34'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.42'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-044' do
  title 'Ensure \'Profile system performance\' is set to \'Administrators, NT SERVICE\WdiServiceHost\''
  desc 'This policy setting allows users to use tools to view the performance of different system processes, which could be abused to allow attackers to determine a system\'s active processes and provide insight into the potential attack surface of the computer.

  The recommended state for this setting is: Administrators, NT SERVICE\WdiServiceHost.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.35'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.43'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeSystemProfilePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'] }
  end
end

control 'windows-045' do
  title 'Ensure \'Replace a process level token\' is set to \'LOCAL SERVICE, NETWORK SERVICE\''
  desc 'This policy setting allows one process or service to start another service or process with a different security access token, which can be used to modify the security access token of that sub-process and result in the escalation of privileges.

  The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.

  Note #2: A Member Server that holds the Web Server (IIS) Role with Web Server Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.

  Note #3: A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.36'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.44'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should eq attribute('se_assign_primary_token_privilege') }
  end
end

control 'windows-046' do
  title 'Ensure \'Restore files and directories\' is set to \'Administrators\''
  desc 'This policy setting determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed up files and directories on computers that run Windows Vista (or newer) in your environment. This user right also determines which users can set valid security principals as object owners; it is similar to the Back up files and directories user right.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.37'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.45'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeRestorePrivilege') { should eq attribute('se_restore_privilege') }
  end
end

control 'windows-047' do
  title 'Ensure \'Shut down the system\' is set to \'Administrators\''
  desc 'This policy setting determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command. Misuse of this user right can result in a denial of service condition.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.38'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.46'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeShutdownPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-048' do
  title 'Ensure \'Synchronize directory service data\' is set to \'No One\' (DC only)'
  desc 'This security setting determines which users and groups have the authority to synchronize all directory service data. This is also known as Active Directory synchronization.

  The recommended state for this setting is: No One.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.39'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.47'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe security_policy do
    its('SeSyncAgentPrivilege') { should eq [] }
  end
end

control 'windows-049' do
  title 'Ensure \'Take ownership of files or other objects\' is set to \'Administrators\''
  desc 'This policy setting allows users to take ownership of files, folders, registry keys, processes, or threads. This user right bypasses any permissions that are in place to protect objects to give ownership to the specified user.

  The recommended state for this setting is: Administrators.

  Note: This user right is considered a "sensitive privilege" for the purposes of auditing.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.40'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.48'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'windows-050' do
  title 'Ensure \'Accounts: Administrator account status\' is set to \'Disabled\''
  desc 'This policy setting enables or disables the Administrator account during normal operation. When a computer is booted into safe mode, the Administrator account is always enabled, regardless of how this setting is configured. Note that this setting will have no impact when applied to the Domain Controllers organizational unit via group policy because Domain Controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe(users.where { uid =~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-500/ }) do
    it { should exist }
    it { should be_disabled }
  end
end

control 'windows-051' do
  title 'Ensure \'Accounts: Block Microsoft accounts\' is set to \'Users can\'t add or log on with Microsoft accounts\''
  desc 'This policy setting prevents users from adding new Microsoft accounts on this computer.

  The recommended state for this setting is: Users can\'t add or log on with Microsoft accounts.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'NoConnectedUser' }
    its('NoConnectedUser') { should eq 3 }
  end
end

control 'windows-052' do
  title 'Ensure \'Accounts: Guest account status\' is set to \'Disabled\''
  desc 'This policy setting determines whether the Guest account is enabled or disabled. The Guest account allows unauthenticated network users to gain access to the system.

  The recommended state for this setting is: Disabled.

  Note: This setting will have no impact when applied to the Domain Controllers organizational unit via group policy because Domain Controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe(users.where { uid =~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-501/ }) do
    it { should exist }
    it { should be_disabled }
  end
end

control 'windows-053' do
  title 'Ensure \'Accounts: Limit local account use of blank passwords to console logon only\' is set to \'Enabled\''
  desc 'This policy setting determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. If you enable this policy setting, local accounts that have blank passwords will not be able to log on to the network from remote client computers. Such accounts will only be able to log on at the keyboard of the computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'LimitBlankPasswordUse' }
    its('LimitBlankPasswordUse') { should eq 1 }
  end
end

control 'windows-054' do
  title 'Configure \'Accounts: Rename administrator account\''
  desc 'The built-in local administrator account is a well-known account name that attackers will target. It is recommended to choose another name for this account, and to avoid names that denote administrative or elevated access accounts. Be sure to also change the default description for the local administrator (through the Computer Management console). On Domain Controllers, since they do not have their own local accounts, this rule refers to the built-in Administrator account that was established when the domain was first created.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe user('Administrator') do
    it { should_not exist }
  end
end

control 'windows-055' do
  title 'Configure \'Accounts: Rename guest account\''
  desc 'The built-in local guest account is another well-known name to attackers. It is recommended to rename this account to something that does not indicate its purpose. Even if you disable this account, which is recommended, ensure that you rename it for added security. On Domain Controllers, since they do not have their own local accounts, this rule refers to the built-in Guest account that was established when the domain was first created.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe user('Guest') do
    it { should_not exist }
  end
end

control 'windows-056' do
  title 'Ensure \'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings\' is set to \'Enabled\''
  desc 'This policy setting allows administrators to enable the more precise auditing capabilities present in Windows Vista.

  The Audit Policy settings available in Windows Server 2003 Active Directory do not yet contain settings for managing the new auditing subcategories. To properly apply the auditing policies prescribed in this baseline, the Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings setting needs to be configured to Enabled.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'SCENoApplyLegacyAuditPolicy' }
    its('SCENoApplyLegacyAuditPolicy') { should eq 1 }
  end
end

control 'windows-057' do
  title 'Ensure \'Audit: Shut down system immediately if unable to log security audits\' is set to \'Disabled\''
  desc 'This policy setting determines whether the system shuts down if it is unable to log Security events. It is a requirement for Trusted Computer System Evaluation Criteria (TCSEC)-C2 and Common Criteria certification to prevent auditable events from occurring if the audit system is unable to log them. Microsoft has chosen to meet this requirement by halting the system and displaying a stop message if the auditing system experiences a failure. When this policy setting is enabled, the system will be shut down if a security audit cannot be logged for any reason.

  If the Audit: Shut down system immediately if unable to log security audits setting is enabled, unplanned system failures can occur. The administrative burden can be significant, especially if you also configure the Retention method for the Security log to Do not overwrite events (clear log manually). This configuration causes a repudiation threat (a backup operator could deny that they backed up or restored data) to become a denial of service (DoS) vulnerability, because a server could be forced to shut down if it is overwhelmed with logon events and other security events that are written to the Security log. Also, because the shutdown is not graceful, it is possible that irreparable damage to the operating system, applications, or data could result. Although the NTFS file system guarantees its integrity when an ungraceful computer shutdown occurs, it cannot guarantee that every data file for every application will still be in a usable form when the computer restarts.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'CrashOnAuditFail' }
    its('CrashOnAuditFail') { should eq 0 }
  end
end

control 'windows-058' do
  title 'Ensure \'Devices: Allowed to format and eject removable media\' is set to \'Administrators\''
  desc 'This policy setting determines who is allowed to format and eject removable NTFS media. You can use this policy setting to prevent unauthorized users from removing data on one computer to access it on another computer on which they have local administrator privileges.

  The recommended state for this setting is: Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'AllocateDASD' }
    its('AllocateDASD') { should cmp == 0 }
  end
end

control 'windows-059' do
  title 'Ensure \'Devices: Prevent users from installing printer drivers\' is set to \'Enabled\''
  desc 'For a computer to print to a shared printer, the driver for that shared printer must be installed on the local computer. This security setting determines who is allowed to install a printer driver as part of connecting to a shared printer.

  The recommended state for this setting is: Enabled.

  Note: This setting does not affect the ability to add a local printer. This setting does not affect Administrators.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M5', 'Schutz vor Schadsoftware', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers') do
    it { should exist }
    it { should have_property 'AddPrinterDrivers' }
    its('AddPrinterDrivers') { should eq 1 }
  end
end

control 'windows-060' do
  title 'Ensure \'Domain controller: Allow server operators to schedule tasks\' is set to \'Disabled\' (DC only)'
  desc 'This policy setting determines whether members of the Server Operators group are allowed to submit jobs by means of the AT schedule facility. The impact of this policy setting configuration should be small for most organizations. Users, including those in the Server Operators group, will still be able to create jobs by means of the Task Scheduler Wizard, but those jobs will run in the context of the account with which the user authenticates when they set up the job.
  Note: An AT Service Account can be modified to select a different account rather than the LOCAL SYSTEM account. To change the account, open System Tools, click Scheduled Tasks, and then click Accessories folder. Then click AT Service Account on the Advanced menu.

  The recommended state for this setting is: Disabled. (DC only)'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'SubmitControl' }
    its('SubmitControl') { should eq 0 }
  end
end

control 'windows-061' do
  title 'Ensure \'Domain controller: LDAP server signing requirements\' is set to \'Require signing\' (DC only)'
  desc "This policy setting determines whether the Lightweight Directory Access Protocol (LDAP) server requires LDAP clients to negotiate data signing.
  The recommended state for this setting is: Require signing.

  Note: Domain member computers must have Network security: LDAP signing requirements (Rule 2.3.11.8) set to Negotiate signing or higher. If not, they will fail to authenticate once the above Require signing value is configured on the Domain Controllers. Fortunately, Negotiate signing is the default in the client configuration.

  Note #2: This policy setting does not have any impact on LDAP simple bind (ldap_simple_bind) or LDAP simple bind through SSL (ldap_simple_bind_s). No Microsoft LDAP clients that are shipped with Windows XP Professional use LDAP simple bind or LDAP simple bind through SSL to talk to a Domain Controller.

  Note #3: Before enabling this setting, you should first ensure that there are no clients (including server-based applications) that are configured to authenticate with Active Directory via unsigned LDAP, because changing this setting will break those applications. Such applications should first be reconfigured to use signed LDAP, Secure LDAP (LDAPS), or IPsec-protected connections. For more information on how to identify whether your DCs are being accessed via unsigned LDAP (and where those accesses are coming from), see this Microsoft TechNet blog article: Identifying Clear Text LDAP binds to your DC's - Practical Windows Security"
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    it { should exist }
    it { should have_property 'LDAPServerIntegrity' }
    its('LDAPServerIntegrity') { should eq 2 }
  end
end

control 'windows-062' do
  title 'Ensure \'Domain controller: Refuse machine account password changes\' is set to \'Disabled\' (DC only)'
  desc 'This security setting determines whether Domain Controllers will refuse requests from member computers to change computer account passwords.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'DC'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RefusePasswordChange' }
    its('RefusePasswordChange') { should eq 0 }
  end
end

control 'windows-063' do
  title 'Ensure \'Domain member: Digitally encrypt or sign secure channel data (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether all secure channel traffic that is initiated by the domain member must be signed or encrypted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSignOrSeal' }
    its('RequireSignOrSeal') { should eq 1 }
  end
end

control 'windows-064' do
  title 'Ensure \'Domain member: Digitally encrypt secure channel data (when possible)\' is set to \'Enabled\''
  desc 'This policy setting determines whether a domain member should attempt to negotiate encryption for all secure channel traffic that it initiates.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'SealSecureChannel' }
    its('SealSecureChannel') { should eq 1 }
  end
end

control 'windows-065' do
  title 'Ensure \'Domain member: Digitally sign secure channel data (when possible)\' is set to \'Enabled\''
  desc 'This policy setting determines whether a domain member should attempt to negotiate whether all secure channel traffic that it initiates must be digitally signed. Digital signatures protect the traffic from being modified by anyone who captures the data as it traverses the network.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'SignSecureChannel' }
    its('SignSecureChannel') { should eq 1 }
  end
end

control 'windows-066' do
  title 'Ensure \'Domain member: Disable machine account password changes\' is set to \'Disabled\''
  desc 'This policy setting determines whether a domain member can periodically change its computer account password. Computers that cannot automatically change their account passwords are potentially vulnerable, because an attacker might be able to determine the password for the system\'s domain account.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'DisablePasswordChange' }
    its('DisablePasswordChange') { should eq 0 }
  end
end

control 'windows-067' do
  title 'Ensure \'Domain member: Maximum machine account password age\' is set to \'30 or fewer days, but not 0\''
  desc 'This policy setting determines the maximum allowable age for a computer account password. By default, domain members automatically change their domain passwords every 30 days.

  The recommended state for this setting is: 30 or fewer days, but not 0.

  Note: A value of 0 does not conform to the benchmark as it disables maximum password age.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should cmp <= 30 }
  end
end

control 'windows-068' do
  title 'Ensure \'Domain member: Require strong (Windows 2000 or later) session key\' is set to \'Enabled\''
  desc 'When this policy setting is enabled, a secure channel can only be established with Domain Controllers that are capable of encrypting secure channel data with a strong (128-bit) session key.

  To enable this policy setting, all Domain Controllers in the domain must be able to encrypt secure channel data with a strong key, which means all Domain Controllers must be running Microsoft Windows 2000 or newer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should exist }
    it { should have_property 'RequireStrongKey' }
    its('RequireStrongKey') { should eq 1 }
  end
end

control 'windows-069' do
  title 'Ensure \'Interactive logon: Do not display last user name\' is set to \'Enabled\''
  desc 'This policy setting determines whether the account name of the last user to log on to the client computers in your organization will be displayed in each computer\'s respective Windows logon screen. Enable this policy setting to prevent intruders from collecting account names visually from the screens of desktop or laptop computers in your organization.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'DontDisplayLastUserName' }
    its('DontDisplayLastUserName') { should eq 1 }
  end
end

control 'windows-070' do
  title 'Ensure \'Interactive logon: Do not require CTRL+ALT+DEL\' is set to \'Disabled\''
  desc 'Microsoft developed this feature to make it easier for users with certain types of physical impairments to log on to computers that run Windows. If users are not required to press CTRL+ALT+DEL, they are susceptible to attacks that attempt to intercept their passwords. If CTRL+ALT+DEL is required before logon, user passwords are communicated by means of a trusted path.

  An attacker could install a Trojan horse program that looks like the standard Windows logon dialog box and capture the user\'s password. The attacker would then be able to log on to the compromised account with whatever level of privilege that user has.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'DisableCAD' }
    its('DisableCAD') { should eq 0 }
  end
end

control 'windows-071' do
  title 'Ensure \'Interactive logon: Machine inactivity limit\' is set to \'900 or fewer second(s), but not 0\''
  desc 'Windows notices inactivity of a logon session, and if the amount of inactive time exceeds the inactivity limit, then the screen saver will run, locking the session.

  The recommended state for this setting is: 900 or fewer second(s), but not 0.

  Note: A value of 0 does not conform to the benchmark as it disables the machine inactivity limit.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should_not eq 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should be <= 900 }
  end
end

control 'windows-072' do
  title 'Configure \'Interactive logon: Message text for users attempting to log on\''
  desc 'This policy setting specifies a text message that displays to users when they log on. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LegalNoticeText' }
    its('LegalNoticeText') { should match(//) }
  end
end

control 'windows-073' do
  title 'Configure \'Interactive logon: Message title for users attempting to log on\''
  desc 'This policy setting specifies the text displayed in the title bar of the window that users see when they log on to the system. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'LegalNoticeCaption' }
    its('LegalNoticeCaption') { should match(//) }
  end
end

control 'windows-074' do
  title 'Ensure \'Interactive logon: Number of previous logons to cache (in case domain controller is not available)\' is set to \'4 or fewer logon(s)\''
  desc 'This policy setting determines whether a user can log on to a Windows domain using cached account information. Logon information for domain accounts can be cached locally to allow users to log on even if a Domain Controller cannot be contacted. This policy setting determines the number of unique users for whom logon information is cached locally. If this value is set to 0, the logon cache feature is disabled. An attacker who is able to access the file system of the server could locate this cached information and use a brute force attack to determine user passwords.

  The recommended state for this setting is: 4 or fewer logon(s).'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.6'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2 and attribute(\'ms_or_dc\') is set to MS') do
    ((attribute('level_1_or_2') == 2) && (attribute('ms_or_dc') == 'MS'))
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    its('CachedLogonsCount') { should cmp <= 4 }
  end
end

control 'windows-075' do
  title 'Ensure \'Interactive logon: Prompt user to change password before expiration\' is set to \'between 5 and 14 days\''
  desc 'This policy setting determines how far in advance users are warned that their password will expire. It is recommended that you configure this policy setting to at least 5 days but no more than 14 days to sufficiently warn users when their passwords will expire.

  The recommended state for this setting is: between 5 and 14 days.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'PasswordExpiryWarning' }
    its('PasswordExpiryWarning') { should cmp <= 14 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'passwordexpirywarning' }
    its('passwordexpirywarning') { should cmp >= 5 }
  end
end

control 'windows-076' do
  title 'Ensure \'Interactive logon: Require Domain Controller Authentication to unlock workstation\' is set to \'Enabled\''
  desc 'Logon information is required to unlock a locked computer. For domain accounts, this security setting determines whether it is necessary to contact a Domain Controller to unlock a computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ForceUnlockLogon' }
    its('ForceUnlockLogon') { should eq 1 }
  end
end

control 'windows-077' do
  title 'Ensure \'Interactive logon: Smart card removal behavior\' is set to \'Lock Workstation\' or higher'
  desc 'This policy setting determines what happens when the smart card for a logged-on user is removed from the smart card reader.

  The recommended state for this setting is: Lock Workstation. Configuring this setting to Force Logoff or Disconnect if a Remote Desktop Services session also conforms to the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should exist }
    it { should have_property 'ScRemoveOption' }
    its('ScRemoveOption') { should match(//) }
  end
end

control 'windows-078' do
  title 'Ensure \'Microsoft network client: Digitally sign communications (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether packet signing is required by the SMB client component.

  Note: When Windows Vista-based computers have this policy setting enabled and they connect to file or print shares on remote servers, it is important that the setting is synchronized with its companion setting, Microsoft network server: Digitally sign communications (always), on those servers. For more information about these settings, see the "Microsoft network client and server: Digitally sign communications (four related settings)" section in Chapter 5 of the Threats and Countermeasures guide.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'windows-079' do
  title 'Ensure \'Microsoft network client: Digitally sign communications (if server agrees)\' is set to \'Enabled\''
  desc 'This policy setting determines whether the SMB client will attempt to negotiate SMB packet signing.

  Note: Enabling this policy setting on SMB clients on your network makes them fully effective for packet signing with all clients and servers in your environment.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

control 'windows-080' do
  title 'Ensure \'Microsoft network client: Send unencrypted password to third-party SMB servers\' is set to \'Disabled\''
  desc 'This policy setting determines whether the SMB redirector will send plaintext passwords during authentication to third-party SMB servers that do not support password encryption.

  It is recommended that you disable this policy setting unless there is a strong business case to enable it. If this policy setting is enabled, unencrypted passwords will be allowed across the network.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should exist }
    it { should have_property 'EnablePlainTextPassword' }
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

control 'windows-081' do
  title 'Ensure \'Microsoft network server: Amount of idle time required before suspending session\' is set to \'15 or fewer minute(s), but not 0\''
  desc 'This policy setting allows you to specify the amount of continuous idle time that must pass in an SMB session before the session is suspended because of inactivity. Administrators can use this policy setting to control when a computer suspends an inactive SMB session. If client activity resumes, the session is automatically reestablished.

  A value of 0 appears to allow sessions to persist indefinitely. The maximum value is 99999, which is over 69 days; in effect, this value disables the setting.

  The recommended state for this setting is: 15 or fewer minute(s), but not 0.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'AutoDisconnect' }
    its('AutoDisconnect') { should eq 15 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'AutoDisconnect' }
    its('AutoDisconnect') { should_not eq 0 }
  end
end

control 'windows-082' do
  title 'Ensure \'Microsoft network server: Digitally sign communications (always)\' is set to \'Enabled\''
  desc 'This policy setting determines whether packet signing is required by the SMB server component. Enable this policy setting in a mixed environment to prevent downstream clients from using the workstation as a network server.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'windows-083' do
  title 'Ensure \'Microsoft network server: Digitally sign communications (if client agrees)\' is set to \'Enabled\''
  desc 'This policy setting determines whether the SMB server will negotiate SMB packet signing with clients that request it. If no signing request comes from the client, a connection will be allowed without a signature if the Microsoft network server: Digitally sign communications (always) setting is not enabled.

  Note: Enable this policy setting on SMB clients on your network to make them fully effective for packet signing with all clients and servers in your environment.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

control 'windows-084' do
  title 'Ensure \'Microsoft network server: Disconnect clients when logon hours expire\' is set to \'Enabled\''
  desc 'This security setting determines whether to disconnect users who are connected to the local computer outside their user account\'s valid logon hours. This setting affects the Server Message Block (SMB) component. If you enable this policy setting you should also enable Network security: Force logoff when logon hours expire (Rule 2.3.11.6).

  If your organization configures logon hours for users, this policy setting is necessary to ensure they are effective.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableForcedLogoff' }
    its('EnableForcedLogoff') { should eq 1 }
  end
end

control 'windows-085' do
  title 'Ensure \'Microsoft network server: Server SPN target name validation level\' is set to \'Accept if provided by client\' or higher\''
  desc 'This policy setting controls the level of validation a computer with shared folders or printers (the server) performs on the service principal name (SPN) that is provided by the client computer when it establishes a session using the server message block (SMB) protocol.

  The server message block (SMB) protocol provides the basis for file and print sharing and other networking operations, such as remote Windows administration. The SMB protocol supports validating the SMB server service principal name (SPN) within the authentication blob provided by a SMB client to prevent a class of attacks against SMB servers referred to as SMB relay attacks. This setting will affect both SMB1 and SMB2.

  The recommended state for this setting is: Accept if provided by client. Configuring this setting to Required from client also conforms to the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'SMBServerNameHardeningLevel' }
    its('SMBServerNameHardeningLevel') { should be >= 1 }
    its('SMBServerNameHardeningLevel') { should be <= 2 }
  end
end

control 'windows-086' do
  title 'Ensure \'Network access: Allow anonymous SID/Name translation\' is set to \'Disabled\''
  desc 'This policy setting determines whether an anonymous user can request security identifier (SID) attributes for another user, or use a SID to obtain its corresponding user name.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

control 'windows-087' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts\' is set to \'Enabled\''
  desc 'This policy setting controls the ability of anonymous users to enumerate the accounts in the Security Accounts Manager (SAM). If you enable this policy setting, users with anonymous connections will not be able to enumerate domain account user names on the systems in your environment. This policy setting also allows additional restrictions on anonymous connections.

  The recommended state for this setting is: Enabled.

  Note: This policy has no effect on Domain Controllers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'RestrictAnonymousSAM' }
    its('RestrictAnonymousSAM') { should eq 1 }
  end
end

control 'windows-088' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts and shares\' is set to \'Enabled\''
  desc 'This policy setting controls the ability of anonymous users to enumerate SAM accounts as well as shares. If you enable this policy setting, anonymous users will not be able to enumerate domain account user names and network share names on the systems in your environment.

  The recommended state for this setting is: Enabled.

  Note: This policy has no effect on Domain Controllers.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'ms_or_dc\') is set to MS') do
    attribute('ms_or_dc') == 'MS'
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should eq 1 }
  end
end

control 'windows-089' do
  title 'Ensure \'Network access: Do not allow storage of passwords and credentials for network authentication\' is set to \'Enabled\''
  desc 'This policy setting determines whether Credential Manager (formerly called Stored User Names and Passwords) saves passwords or credentials for later use when it gains domain authentication.

  The recommended state for this setting is: Enabled.

  Note: Changes to this setting will not take effect until Windows is restarted.'
  impact 0.5
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.4'
  tag 'level': '2'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('This Control only executes if attribute(\'level_1_or_2\') is set to 2') do
    attribute('level_1_or_2') == 2
  end
  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'DisableDomainCreds' }
    its('DisableDomainCreds') { should eq 1 }
  end
end

control 'windows-090' do
  title 'Ensure \'Network access: Let Everyone permissions apply to anonymous users\' is set to \'Disabled\''
  desc 'This policy setting determines what additional permissions are assigned for anonymous connections to the computer.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'EveryoneIncludesAnonymous' }
    its('EveryoneIncludesAnonymous') { should eq 1 }
  end
end

control 'windows-091' do
  title 'Configure \'Network access: Named Pipes that can be accessed anonymously\''
  desc 'This policy setting determines which communication sessions, or pipes, will have attributes and permissions that allow anonymous access.
  The recommended state for this setting is: LSARPC, NETLOGON, SAMR and (when the legacy Computer Browser service is enabled) BROWSER.

  The recommended state for this setting is:
  - Level 1 - Domain Controller. The recommended state for this setting is: LSARPC, NETLOGON, SAMR and (when the legacy Computer Browser service is enabled) BROWSER.
  - Level 1 - Member Server. The recommended state for this setting is: <blank> (i.e. None), or (when the legacy Computer Browser service is enabled) BROWSER.

  Note: A Member Server that holds the Remote Desktop Services Role with Remote Desktop Licensing Role Service will require a special exception to this recommendation, to allow the HydraLSPipe and TermServLicensing Named Pipes to be accessed anonymously.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.3.10.6', '2.3.10.7']
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'NullSessionPipes' }
    its('NullSessionPipes') { should eq attribute('hklm_null_session_pipes') }
  end
end

control 'windows-092' do
  title 'Configure \'Network access: Remotely accessible registry paths\''
  desc 'This policy setting determines which registry paths will be accessible over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.

  Note: This setting does not exist in Windows XP. There was a setting with that name in Windows XP, but it is called "Network access: Remotely accessible registry paths and subpaths" in Windows Server 2003, Windows Vista, and Windows Server 2008 (non-R2).

  Note #2: When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor\'s display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.

  The recommended state for this setting is:
  System\CurrentControlSet\Control\ProductOptions
  System\CurrentControlSet\Control\Server Applications
  Software\Microsoft\Windows NT\CurrentVersion'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths') do
    it { should exist }
    it { should have_property 'Machine' }
    its('Machine') { should eq ['System\\CurrentControlSet\\Control\\ProductOptions', 'System\\CurrentControlSet\\Control\\Server Applications', 'Software\\Microsoft\\Windows NT\\CurrentVersion'] }
  end

end

control 'windows-093' do
  title 'Configure \'Network access: Remotely accessible registry paths and sub-paths\''
  desc 'This policy setting determines which registry paths and sub-paths will be accessible over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.

  Note: In Windows XP this setting is called "Network access: Remotely accessible registry paths," the setting with that same name in Windows Vista, Windows Server 2008 (non-R2), and Windows Server 2003 does not exist in Windows XP.

  Note #2: When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor\'s display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.

  The recommended state for this setting is:
  System\CurrentControlSet\Control\Print\Printers
  System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server
  Software\Microsoft\Windows NT\CurrentVersion\Print
  Software\Microsoft\Windows NT\CurrentVersion\Windows
  System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server
  System\CurrentControlSet\Control\Terminal
  Server\UserConfig System\CurrentControlSet\Control\Terminal
  Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib
  System\CurrentControlSet\Services\SysmonLog

  The recommended state for servers that hold the Active Directory Certificate Services Role with Certification Authority Role Service includes the above list and:
  System\CurrentControlSet\Services\CertSvc

  The recommended state for servers that have the WINS Server Feature installed includes the above list and:
  System\CurrentControlSet\Services\WINS'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration', 'SYS.1.2.2.M8', 'Schutz der Systemintegritat']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  wins_installed = windows_feature('WINS').installed?
  ad_cert_installed = windows_feature('AD-Certificate').installed?

  if !wins_installed && !ad_cert_installed
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq ['System\\CurrentControlSet\\Control\\Print\\Printers', 'System\\CurrentControlSet\\Services\\Eventlog', 'Software\\Microsoft\\OLAP Server', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', 'System\\CurrentControlSet\\Control\\ContentIndex', 'System\\CurrentControlSet\\Control\\Terminal Server', 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', 'System\\CurrentControlSet\\Services\\SysmonLog'] }
    end
  elsif wins_installed && !ad_cert_installed
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq ['System\\CurrentControlSet\\Control\\Print\\Printers', 'System\\CurrentControlSet\\Services\\Eventlog', 'Software\\Microsoft\\OLAP Server', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', 'System\\CurrentControlSet\\Control\\ContentIndex', 'System\\CurrentControlSet\\Control\\Terminal Server', 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', 'System\\CurrentControlSet\\Services\\SysmonLog', 'System\\CurrentControlSet\\Services\\WINS'] }
    end
  elsif !wins_installed && ad_cert_installed
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq ['System\\CurrentControlSet\\Control\\Print\\Printers', 'System\\CurrentControlSet\\Services\\Eventlog', 'Software\\Microsoft\\OLAP Server', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', 'System\\CurrentControlSet\\Control\\ContentIndex', 'System\\CurrentControlSet\\Control\\Terminal Server', 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', 'System\\CurrentControlSet\\Services\\SysmonLog', 'System\\CurrentControlSet\\Services\\CertSvc'] }
    end
  elsif wins_installed && ad_cert_installed
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
      it { should exist }
      it { should have_property 'Machine' }
      its('Machine') { should eq ['System\\CurrentControlSet\\Control\\Print\\Printers', 'System\\CurrentControlSet\\Services\\Eventlog', 'Software\\Microsoft\\OLAP Server', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', 'System\\CurrentControlSet\\Control\\ContentIndex', 'System\\CurrentControlSet\\Control\\Terminal Server', 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', 'System\\CurrentControlSet\\Services\\SysmonLog', 'System\\CurrentControlSet\\Services\\CertSvc', 'System\\CurrentControlSet\\Services\\WINS'] }
    end
  end
end

control 'windows-094' do
  title 'Ensure \'Network access: Restrict anonymous access to Named Pipes and Shares\' is set to \'Enabled\''
  desc 'When enabled, this policy setting restricts anonymous access to only those shares and pipes that are named in the Network access: Named pipes that can be accessed anonymously and Network access: Shares that can be accessed anonymously settings. This policy setting controls null session access to shares on your computers by adding RestrictNullSessAccess with the value 1 in the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters
  registry key. This registry value toggles null session shares on or off to control whether the server service restricts unauthenticated clients\' access to named resources.
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'RestrictNullSessAccess' }
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

control 'windows-095' do
  title 'Ensure \'Network access: Restrict clients allowed to make remote calls to SAM\' is set to \'Administrators: Remote Access: Allow\''
  desc 'This policy setting allows you to restrict remote RPC connections to SAM.

  The recommended state for this setting is: Administrators: Remote Access: Allow.

  Note: A Windows 10 R1607, Server 2016 or newer OS is required to access and set this value in Group Policy.'
  impact 1.0
  tag 'windows': %w[2016 2019]
  tag 'profile': ['Member Server']
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.11'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  only_if('Only for Windows Server 2016, 2019 and if attribute(\'ms_or_dc\') is set to MS') do
    (((os[:name].include? '2016') || (os[:name].include? '2019')) && attribute('ms_or_dc') == 'MS')
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'restrictremotesam' }
    its('restrictremotesam') { should eq 'O:BAG:BAD:(A;;RC;;;BA)' }
  end
end

control 'windows-096' do
  title 'Ensure \'Network access: Shares that can be accessed anonymously\' is set to \'None\''
  desc 'This policy setting determines which network shares can be accessed by anonymous users. The default configuration for this policy setting has little effect because all users have to be authenticated before they can access shared resources on the server.

  The recommended state for this setting is: <blank> (i.e. None).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.12'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'NullSessionShares' }
    its('NullSessionShares') { should eq [''] }
  end
end

control 'windows-097' do
  title 'Ensure \'Network access: Sharing and security model for local accounts\' is set to \'Classic - local users authenticate as themselves\''
  desc 'This policy setting determines how network logons that use local accounts are authenticated. The Classic option allows precise control over access to resources, including the ability to assign different types of access to different users for the same resource. The Guest only option allows you to treat all users equally. In this context, all users authenticate as Guest only to receive the same access level to a given resource.

  The recommended state for this setting is: Classic - local users authenticate as themselves.

  Note: This setting does not affect interactive logons that are performed remotely by using such services as Telnet or Remote Desktop Services (formerly called Terminal Services).'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.11'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.13'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein

  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'ForceGuest' }
    its('ForceGuest') { should eq 0 }
  end
end

control 'windows-098' do
  title 'Ensure \'Network security: Allow Local System to use computer identity for NTLM\' is set to \'Enabled\''
  desc 'This policy setting determines whether Local System services that use Negotiate when reverting to NTLM authentication can use the computer identity. This policy is supported on at least Windows 7 or Windows Server 2008 R2.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'UseMachineId' }
    its('UseMachineId') { should eq 1 }
  end
end

control 'windows-099' do
  title 'Ensure \'Network security: Allow LocalSystem NULL session fallback\' is set to \'Disabled\''
  desc 'This policy setting determines whether NTLM is allowed to fall back to a NULL session when used with LocalSystem.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'AllowNullSessionFallback' }
    its('AllowNullSessionFallback') { should eq 0 }
  end
end

control 'windows-100' do
  title 'Ensure \'Network Security: Allow PKU2U authentication requests to this computer to use online identities\' is set to \'Disabled\''
  desc 'This setting determines if online identities are able to authenticate to this computer.

  The Public Key Cryptography Based User-to-User (PKU2U) protocol introduced in Windows 7 and Windows Server 2008 R2 is implemented as a security support provider (SSP). The SSP enables peer-to-peer authentication, particularly through the Windows 7 media and file sharing feature called Homegroup, which permits sharing between computers that are not members of a domain.

  With PKU2U, a new extension was introduced to the Negotiate authentication package, Spnego.dll. In previous versions of Windows, Negotiate decided whether to use Kerberos or NTLM for authentication. The extension SSP for Negotiate, Negoexts.dll, which is treated as an authentication protocol by Windows, supports Microsoft SSPs including PKU2U.

  When computers are configured to accept authentication requests by using online IDs, Negoexts.dll calls the PKU2U SSP on the computer that is used to log on. The PKU2U SSP obtains a local certificate and exchanges the policy between the peer computers. When validated on the peer computer, the certificate within the metadata is sent to the logon peer for validation and associates the user\'s certificate to a security token and the logon process completes.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u') do
    it { should exist }
    it { should have_property 'AllowOnlineID' }
    its('AllowOnlineID') { should eq 0 }
  end
end

control 'windows-101' do
  title 'Ensure \'Network security: Configure encryption types allowed for Kerberos\' is set to \'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types\''
  desc 'This policy setting allows you to set the encryption types that Kerberos is allowed to use.

  The recommended state for this setting is: RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    it { should exist }
    it { should have_property 'SupportedEncryptionTypes' }
    its('SupportedEncryptionTypes') { should eq 2_147_483_644 }
  end
end

control 'windows-102' do
  title 'Ensure \'Network security: Do not store LAN Manager hash value on next password change\' is set to \'Enabled\''
  desc 'This policy setting determines whether the LAN Manager (LM) hash value for the new password is stored when the password is changed. The LM hash is relatively weak and prone to attack compared to the cryptographically stronger Microsoft Windows NT hash. Since LM hashes are stored on the local computer in the security database, passwords can then be easily compromised if the database is attacked.

  **Note:** Older operating systems and some third-party applications may fail when this policy setting is enabled. Also, note that the password will need to be changed on all accounts after you enable this setting to gain the proper benefit.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'NoLMHash' }
    its('NoLMHash') { should eq 1 }
  end
end

control 'windows-103' do
  title 'Ensure \'Network security: Force logoff when logon hours expire\' is set to \'Enabled\''
  desc 'This policy setting determines whether to disconnect users who are connected to the local computer outside their user account\'s valid logon hours. This setting affects the Server Message Block (SMB) component. If you enable this policy setting you should also enable **Microsoft network server: Disconnect clients when logon hours expire** (Rule 2.3.9.4).

  The recommended state for this setting is: Enabled.

  Rationale: If this setting is disabled, a user could remain connected to the computer outside of their allotted logon hours.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should exist }
    it { should have_property 'EnableForcedLogOff' }
    its('EnableForcedLogOff') { should eq 1 }
  end
end

control 'windows-104' do
  title 'Ensure \'Network security: LAN Manager authentication level\' is set to \'Send NTLMv2 response only. Refuse LM\''
  desc 'LAN Manager (LM) was a family of early Microsoft client/server software (predating Windows NT) that allowed users to link personal computers together on a single network. LM network capabilities included transparent file and print sharing, user security features, and network administration tools. In Active Directory domains, the Kerberos protocol is the default authentication protocol. However, if the Kerberos protocol is not negotiated for some reason, Active Directory will use LM, NTLM, or NTLMv2. LAN Manager authentication includes the LM, NTLM, and NTLM version 2 (NTLMv2) variants, and is the protocol that is used to authenticate all Windows clients when they perform the following operations:

  * Join a domain
  * Authenticate between Active Directory forests
  * Authenticate to down-level domains
  * Authenticate to computers that do not run Windows 2000, Windows Server 2003, or Windows XP
  * Authenticate to computers that are not in the domain
  The Network security: LAN Manager authentication level setting determines which challenge/response authentication protocol is used for network logons. This choice affects the level of authentication protocol used by clients, the level of session security negotiated, and the level of authentication accepted by servers.

  The recommended state for this setting is: Send NTLMv2 response only. Refuse LM  NTLM.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should exist }
    it { should have_property 'LmCompatibilityLevel' }
    its('LmCompatibilityLevel') { should eq 5 }
  end
end

control 'windows-105' do
  title 'Ensure \'Network security: LDAP client signing requirements\' is set to \'Negotiate signing\' or higher\''
  desc 'This policy setting determines the level of data signing that is requested on behalf of clients that issue LDAP BIND requests.

  **Note:** This policy setting does not have any impact on LDAP simple bind (ldap_simple_bind) or LDAP simple bind through SSL (ldap_simple_bind_s). No Microsoft LDAP clients that are included with Windows XP Professional use ldap_simple_bind or ldap_simple_bind_s to communicate with a domain controller.

  The recommended state for this setting is: Negotiate signing. Configuring this setting to Require signing also conforms with the benchmark.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP') do
    it { should exist }
    it { should have_property 'LDAPClientIntegrity' }
    its('LDAPClientIntegrity') { should eq 1 }
  end
end

control 'windows-106' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
  desc 'This policy setting determines which behaviors are allowed by clients for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

  The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'NTLMMinClientSec' }
    its('NTLMMinClientSec') { should eq 536870912 }
  end
end

control 'windows-107' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\''
  desc ' This policy setting determines which behaviors are allowed by servers for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

  The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. **Note:** These values are dependent on the **Network security: LAN Manager Authentication Level** security setting value.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.10'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.10'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should exist }
    it { should have_property 'NTLMMinServerSec' }
    its('NTLMMinServerSec') { should eq 536870912 }
  end
end

control 'windows-108' do
  title 'Ensure \'Shutdown: Allow system to be shut down without having to log on\' is set to \'Disabled\''
  desc 'This policy setting determines whether a computer can be shut down when a user is not logged on. If this policy setting is enabled, the shutdown command is available on the Windows logon screen. It is recommended to disable this policy setting to restrict the ability to shut down the computer to users with credentials on the system.

  The recommended state for this setting is: Disabled. **Note:** In Server 2008 R2 and older versions, this setting had no impact on Remote Desktop (RDP) / Terminal Services sessions - it only affected the local console. However, Microsoft changed the behavior in Windows Server 2012 (non-R2) and above, where if set to Enabled, RDP sessions are also allowed to shut down or restart the server.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.13.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.13.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ShutdownWithoutLogon' }
    its('ShutdownWithoutLogon') { should eq 0 }
  end
end

control 'windows-109' do
  title 'Ensure \'System objects: Require case insensitivity for non-Windows subsystems\' is set to \'Enabled\''
  desc 'This policy setting determines whether case insensitivity is enforced for all subsystems. The Microsoft Win32 subsystem is case insensitive. However, the kernel supports case sensitivity for other subsystems, such as the Portable Operating System Interface for UNIX (POSIX). Because Windows is case insensitive (but the POSIX subsystem will support case sensitivity), failure to enforce this policy setting makes it possible for a user of the POSIX subsystem to create a file with the same name as another file by using mixed case to label it. Such a situation can block access to these files by another user who uses typical Win32 tools, because only one of the files will be available.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel') do
    it { should exist }
    it { should have_property 'ObCaseInsensitive' }
    its('ObCaseInsensitive') { should eq 1 }
  end
end

control 'windows-110' do
  title 'Ensure \'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)\' is set to \'Enabled\''
  desc 'This policy setting determines the strength of the default discretionary access control list (DACL) for objects. Active Directory maintains a global list of shared system resources, such as DOS device names, mutexes, and semaphores. In this way, objects can be located and shared among processes. Each type of object is created with a default DACL that specifies who can access the objects and what permissions are granted.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager') do
    it { should exist }
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should eq 1 }
  end
end

control 'windows-111' do
  title 'Ensure \'User Account Control: Admin Approval Mode for the Built-in Administrator account\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of Admin Approval Mode for the built-in Administrator account.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M4', 'Sichere Konfiguration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'FilterAdministratorToken' }
    its('FilterAdministratorToken') { should eq 1 }
  end
end

control 'windows-112' do
  title 'Ensure \'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop\' is set to \'Disabled\''
  desc 'This policy setting controls whether User Interface Accessibility (UIAccess or UIA) programs can automatically disable the secure desktop for elevation prompts used by a standard user.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableUIADesktopToggle' }
    its('EnableUIADesktopToggle') { should eq 0 }
  end
end

control 'windows-113' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode\' is set to \'Prompt for consent on the secure desktop\''
  desc 'This policy setting controls the behavior of the elevation prompt for administrators.

  The recommended state for this setting is: Prompt for consent on the secure desktop.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ConsentPromptBehaviorAdmin' }
    its('ConsentPromptBehaviorAdmin') { should eq 2 }
  end
end

control 'windows-114' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for standard users\' is set to \'Automatically deny elevation requests\''
  desc 'This policy setting controls the behavior of the elevation prompt for standard users.

  The recommended state for this setting is: Automatically deny elevation requests.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'ConsentPromptBehaviorUser' }
    its('ConsentPromptBehaviorUser') { should eq 0 }
  end
end

control 'windows-115' do
  title 'Ensure \'User Account Control: Detect application installations and prompt for elevation\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of application installation detection for the computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableInstallerDetection' }
    its('EnableInstallerDetection') { should eq 1 }
  end
end

control 'windows-116' do
  title 'Ensure \'User Account Control: Only elevate UIAccess applications that are installed in secure locations\' is set to \'Enabled\''
  desc 'This policy setting controls whether applications that request to run with a User Interface Accessibility (UIAccess) integrity level must reside in a secure location in the file system. Secure locations are limited to the following: - &#x2026;\\Program Files\\, including subfolders - &#x2026;\\Windows\\system32\\ - &#x2026;\\Program Files (x86)\\, including subfolders for 64-bit versions of Windows

  **Note:** Windows enforces a public key infrastructure (PKI) signature check on any interactive application that requests to run with a UIAccess integrity level regardless of the state of this security setting.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableSecureUIAPaths' }
    its('EnableSecureUIAPaths') { should eq 1 }
  end
end

control 'windows-117' do
  title 'Ensure \'User Account Control: Run all administrators in Admin Approval Mode\' is set to \'Enabled\''
  desc 'This policy setting controls the behavior of all User Account Control (UAC) policy settings for the computer. If you change this policy setting, you must restart your computer.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.7'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.7'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableLUA' }
    its('EnableLUA') { should eq 1 }
  end
end

control 'windows-118' do
  title 'Ensure \'User Account Control: Switch to the secure desktop when prompting for elevation\' is set to \'Enabled\''
  desc 'This policy setting controls whether the elevation request prompt is displayed on the interactive user\'s desktop or the secure desktop.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.8'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.8'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'PromptOnSecureDesktop' }
    its('PromptOnSecureDesktop') { should eq 1 }
  end
end

control 'windows-119' do
  title 'Ensure \'User Account Control: Virtualize file and registry write failures to per-user locations\' is set to \'Enabled\''
  desc 'This policy setting controls whether application write failures are redirected to defined registry and file system locations. This policy setting mitigates applications that run as administrator and write run-time application data to: - %ProgramFiles%, - %Windir%, - %Windir%\\system32, or - HKEY_LOCAL_MACHINE\\Software.

  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w[2012R2 2016 2019]
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.9'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.9'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration', 'SYS.1.2.2.M6', 'Sichere Authentisierung und Autorisierung']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should exist }
    it { should have_property 'EnableVirtualization' }
    its('EnableVirtualization') { should eq 1 }
  end
end
