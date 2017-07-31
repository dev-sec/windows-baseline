# encoding: utf-8

windows_services_harden = attribute('windows_services_harden', default: true, description: 'Should we ensure services hardening')

if windows_services_harden
  title 'Microsoft Windows services hardening'

  control 'services-1' do
    impact 0.7
    title 'Services to be disabled'
    %w(
      iphlpsvc
      lldtsvc
      NcaSvc
      SSDPSRV
      upnphost
      W3SVC
      WinHttpAutoProxySvc
      Xbox
    ).each do |svc|
      describe service(svc.to_s) do
        it { should_not be_running }
      end
    end
  end
end
