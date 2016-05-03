# encoding: utf-8

title 'User Rights Assignment'

control 'cis-access-cred-manager-2.2.1' do
  impact 0.7
  title '2.2.1 Set Access Credential Manager as a trusted caller to No One'
  desc 'Set Access Credential Manager as a trusted caller to No One'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { is_expected.to be_nil }
  end
end

control 'cis-network-access-2.2.2' do
  impact 0.7
  title '2.2.2 Set Access this computer from the network'
  desc 'Set Access this computer from the network'
  describe security_policy do
    its('SeNetworkLogonRight') { is_expected.to_not be_nil }
  end
end

control 'cis-act-as-os-2.2.3' do
  impact 0.7
  title '2.2.3 Set Act as part of the operating system to No One'
  desc 'Set Act as part of the operating system to No One'
  describe security_policy do
    its('SeTcbPrivilege') { is_expected.to be_nil }
  end
end

control 'cis-add-workstations-2.2.4' do
  impact 0.7
  title '2.2.4 Set Add workstations to domain to Administrators'
  desc 'Set Add workstations to domain to Administrators'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq '*S-1-5-32-544' }
  end
end

control 'cis-adjust-memory-quotas-2.2.5' do
  impact 0.7
  title '2.2.5 Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc 'Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should match(/\*S-1-5-19,?/) }
    its('SeIncreaseQuotaPrivilege') { should match(/\*S-1-5-20,?/) }
    its('SeIncreaseQuotaPrivilege') { should match(/\*S-1-5-32-544,?/) }
  end
end
