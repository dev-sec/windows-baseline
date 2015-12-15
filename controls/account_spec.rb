# encoding: utf-8
# copyright: 2015, Chef Software, Inc
# license: All rights reserved

title 'Windows Account Configuration'

rule 'windows-account-100' do
  impact 1.0
  title 'Windows Remote Desktop Configured to Only Allow System Administrators Access'
  describe security_policy do
    # verifies that only the 'Administrators' group has remote access
    its('SeRemoteInteractiveLogonRight') { should eq '*S-1-5-32-544' }
  end
end

rule 'windows-account-101' do
  impact 1.0
  title 'Windows Default Guest Account is Disabled'
  describe security_policy do
    its('EnableGuestAccount') { should eq 0 }
  end
end

rule 'windows-account-102' do
  impact 1.0
  title 'Windows Password Complexity is Enabled'
  desc 'Password must meet complexity requirement'
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

rule 'windows-account-103' do
  impact 1.0
  title 'Minimum Windows Password Length Configured to be at Least 8 Characters'
  desc 'Minimum password length'
  describe security_policy do
    # TODO: check that the number is greater than 8
    its('MinimumPasswordLength') { should_not eq 0 }
  end
end

rule 'windows-account-104' do
  impact 1.0
  title 'Set Windows Account lockout threshold'
  desc 'Account lockout threshold, see https://technet.microsoft.com/en-us/library/hh994574.aspx'
  describe security_policy do
    # TODO: setting above 4 and below 10
    its('LockoutBadCount') { should_not eq 0 }
  end
end

rule 'windows-account-105' do
  impact 1.0
  title 'Windows Account Lockout Counter Configured to Wait at Least 30 Minutes Before Reset'
  desc 'Reset lockout counter after, see https://technet.microsoft.com/en-us/library/hh994568.aspx'
  describe security_policy do
    # TODO: make time variable for ranges
    its('ResetLockoutCount') { should_not eq 0 }
  end
end

rule 'windows-account-106' do
  impact 1.0
  title 'Windows Account Lockout Duration Configured to at Least 30 Minutes'
  desc 'Account lockout duration, see https://technet.microsoft.com/en-us/library/hh994569.aspx'
  describe security_policy do
    # TODO: make time variable for ranges
    its('LockoutDuration') { should_not eq 0 }
  end
end
