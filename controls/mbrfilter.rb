# encoding: utf-8

mbrfilter_present = attribute('mbrfilter_present', default: false, description: 'Should we control presence of Cisco Talos mbrfilter')

if mbrfilter_present
  title 'Cisco Talos'

  control 'mbrfilter-1' do
    impact 0.7
    title 'mbrfilter installed'
    desc 'Search presence of mbrfilter'
    ref url: 'https://github.com/Cisco-Talos/MBRFilter/blob/d9b17accac6e9a85861029c216d9f4117a498f56/README.txt'
    describe file('c:\Windows\mbrfilter.sys') do
      it { should be_file }
    end
    describe registry_key('HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}') do
      it { should exist }
    end
  end
end
