# encoding: utf-8

tls12_check = attribute('tls12_check', default: false, description: 'Should we control that TLS 1.2 Support is enabled - Ws2008+')

if tls12_check
  title 'TLS 1.2 support'

  control 'tls12-1' do
    impact 0.7
    title 'TLS 1.2 check'
    desc 'Ensure that TLS 1.2 is enabled in registry - reboot required'
    ref url: 'https://technet.microsoft.com/en-us/library/dd560644(v=ws.10).aspx'
    ref url: 'https://support.microsoft.com/en-us/help/245030/how-to-restrict-the-use-of-certain-cryptographic-algorithms-and-protoc'
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 1 }
    end
  end

  control 'sslv3-1' do
    impact 0.7
    title 'SSLv3 check'
    desc 'Ensure that SSLv3 and older are disabled in registry'
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server') do
      it { should exist }
      its('DisabledByDefault') { should eq 0 }
      its('Enabled') { should eq 0 }
    end
  end

end
