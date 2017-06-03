# encoding: utf-8

ipv6_tunnels = attribute('ipv6_tunnels', default: false, description: 'Should IPv6 tunnels be present')

unless ipv6_tunnels
  title 'Microsoft IPv6'

  control 'ipv6-1' do
    impact 0.7
    title 'IPv6 Tunnels: ISATAP'
    desc 'Ensure ISATAP is disabled and no interface is present'
    describe command('ipconfig /all | findstr /i "isatap"') do
      its('stdout') { should eq '' }
    end
  end

  control 'ipv6-2' do
    impact 0.7
    title 'IPv6 Tunnels: Teredo'
    desc 'Ensure Teredo is disabled and no interface is present'
    describe command('ipconfig /all | findstr /i "Teredo"') do
      its('stdout') { should eq '' }
    end
  end

end
