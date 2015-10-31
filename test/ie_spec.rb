# encoding: utf-8
# copyright: 2015, Vulcano Security GmbH
# license: All rights reserved
# title: Windows Audit & Logging Configuration

rule 'windows-ie-101' do
  impact 1.0
  title 'IE 64-bit tab'
  # TODO: we may need to check all users as well
  describe group_policy('Windows Components\\Internet Explorer\\Internet Control Panel\\Advanced Page') do
    its('Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows') { should eq 1 }
  end
end

rule 'windows-ie-102' do
  impact 1.0
  title 'Run antimalware programs against ActiveX controls'
  # TODO: we may need to check all users as well
  describe group_policy('Windows Components\\Internet Explorer\\Internet Control Panel\\Security Page\\Internet Zone') do
    its("Don't run antimalware programs against ActiveX controls") { should eq 0 }
  end
end
