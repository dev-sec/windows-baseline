# frozen_string_literal: true

title 'account policies'

control 'windows-001' do
  title 'Ensure \'Enforce password history\' is set to \'24 or more password(s)\''
  desc 'This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password. The value for this policy setting must be between 0 and 24 passwords. The default value for Windows Vista is 0 passwords, but the default setting in a domain is 24 passwords. To maintain the effectiveness of this policy setting, use the Minimum password age setting to prevent users from repeatedly changing their password.

  The recommended state for this setting is: 24 or more password(s).'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('PasswordHistorySize') { should be >= input('password_history_size') }
  end
end

control 'windows-002' do
  title 'Ensure \'Maximum password age\' is set to \'60 or fewer days, but not 0\''
  desc 'This policy setting defines how long a user can use their password before it expires.

  Values for this policy setting range from 0 to 999 days. If you set the value to 0, the password will never expire.

  Because attackers can crack passwords, the more frequently you change the password the less opportunity an attacker has to use a cracked password. However, the lower this value is set, the higher the potential for an increase in calls to help desk support due to users having to change their password or forgetting which password is current.

  The recommended state for this setting is 60 or fewer days, but not 0.'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MaximumPasswordAge') { should be <= input('maximum_password_age') }
  end
  describe security_policy do
    its('MaximumPasswordAge') { should be.positive? }
  end
end

control 'windows-003' do
  title 'Ensure \'Minimum password age\' is set to \'1 or more day(s)\''
  desc 'This policy setting determines the number of days that you must use a password before you can change it. The range of values for this policy setting is between 1 and 999 days. (You may also set the value to 0 to allow immediate password changes.) The default value for this setting is 0 days.

  The recommended state for this setting is: 1 or more day(s).'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

control 'windows-004' do
  title 'Ensure \'Minimum password length\' is set to \'14 or more character(s)\''
  desc 'This policy setting determines the least number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps "pass phrase" is a better term than "password." In Microsoft Windows 2000 and newer, pass phrases can be quite long and can include spaces. Therefore, a phrase such as "I want to drink a $5 milkshake" is a valid pass phrase; it is a considerably stronger password than an 8 or 10 character string of random numbers and letters, and yet is easier to remember. Users must be educated about the proper selection and maintenance of passwords, especially with regard to password length. In enterprise environments, the ideal value for the Minimum password length setting is 14 characters, however you should adjust this value to meet your organization\'s business requirements.

  The recommended state for this setting is: 14 or more character(s). '
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.4'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.4'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

control 'windows-005' do
  title 'Ensure \'Password must meet complexity requirements\' is set to \'Enabled\''
  desc 'This policy setting checks all new passwords to ensure that they meet basic requirements for strong passwords.
  When this policy is enabled, passwords must meet the following minimum requirements: -- Not contain the user\'s account name or parts of the user\'s full name that exceed two consecutive characters
  -- Be at least six characters in length
  -- Contain characters from three of the following four categories:
  ---- English uppercase characters (A through Z)
  ---- English lowercase characters (a through z)
  ---- Base 10 digits (0 through 9)
  ---- Non-alphabetic characters (for example, !, $, #, %)
  ---- A catch-all category of any Unicode character that does not fall under the previous four categories. This fifth category can be regionally specific.
  Each additional character in a password increases its complexity exponentially. For instance, a seven-character, all lower-case alphabetic password would have 267 (approximately 8 x 109 or 8 billion) possible combinations. At 1,000,000 attempts per second (a capability of many password-cracking utilities), it would only take 133 minutes to crack. A seven-character alphabetic password with case sensitivity has 527 combinations. A seven-character case-sensitive alphanumeric password without punctuation has 627 combinations. An eight-character password has 268 (or 2 x 1011) possible combinations. Although this might seem to be a large number, at 1,000,000 attempts per second it would take only 59 hours to try all possible passwords. Remember, these times will significantly increase for passwords that use ALT characters and other special keyboard characters such as "!" or "@". Proper use of the password settings can help make it difficult to mount a brute force attack.
  The recommended state for this setting is: Enabled.'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.5'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.5'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

control 'windows-006' do
  title 'Ensure \'Store passwords using reversible encryption\' is set to \'Disabled\''
  desc 'This policy setting determines whether the operating system stores passwords in a way that uses reversible encryption, which provides support for application protocols that require knowledge of the user\'s password for authentication purposes. Passwords that are stored with reversible encryption are essentially the same as plaintext versions of the passwords.

  The recommended state for this setting is: Disabled.'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.6'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.6'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

control 'windows-007' do
  title 'Ensure \'Account lockout duration\' is set to \'15 or more minute(s)\''
  desc 'This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked out account will remain unavailable. If the value for this policy setting is configured to 0, locked out accounts will remain locked out until an administrator manually unlocks them.

  Although it might seem like a good idea to configure the value for this policy setting to a high value, such a configuration will likely increase the number of calls that the help desk receives to unlock accounts locked by mistake. Users should be aware of the length of time a lock remains in place, so that they realize they only need to call the help desk if they have an extremely urgent need to regain access to their computer.

  The recommended state for this setting is: 15 or more minute(s).'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.1'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.1'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration']
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('LockoutDuration') { should be >= 15 }
  end
end

control 'windows-008' do
  title 'Ensure \'Account lockout threshold\' is set to \'10 or fewer invalid logon attempt(s), but not 0\''
  desc 'This policy setting determines the number of failed logon attempts before the account is locked. Setting this policy to 0 does not conform to the benchmark as doing so disables the account lockout threshold.

  The recommended state for this setting is: 10 or fewer invalid logon attempt(s), but not 0.'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.2'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.2'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('LockoutBadCount') { should be <= 10 }
  end
  describe security_policy do
    its('LockoutBadCount') { should be.positive? }
  end
end

control 'windows-009' do
  title 'Ensure \'Reset account lockout counter after\' is set to \'15 or more minute(s)\''
  desc 'This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If the Account lockout threshold is defined, this reset time must be less than or equal to the value for the Account lockout duration setting.
  If you leave this policy setting at its default value or configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack. An attacker could maliciously perform a number of failed logon attempts on all users in the organization, which will lock out their accounts. If no policy were determined to reset the account lockout, it would be a manual task for administrators. Conversely, if a reasonable time value is configured for this policy setting, users would be locked out for a set period until all of the accounts are unlocked automatically.

  The recommended state for this setting is: 15 or more minute(s).'
  impact 1.0
  tag 'windows': %w(2012R2 2016 2019)
  tag 'profile': ['Domain Controller', 'Member Server']
  tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.3'
  tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.3'
  tag 'level': '1'
  tag 'bsi': ['SYS.1.2.2.M3', 'Sichere Administration'] # FIXME: check Baustein
  ref 'IT-Grundschutz-Kompendium', url: 'https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/itgrundschutzKompendium_node.html'
  ref 'Umsetzungshinweise zum Baustein SYS.1.2.2: Windows Server 2012', url: 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-Grundschutz-Modernisierung/UH_Windows_Server_2012.html'
  ref 'Center for Internet Security', url: 'https://www.cisecurity.org/'
  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end
