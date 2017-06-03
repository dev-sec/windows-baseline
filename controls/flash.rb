# encoding: utf-8

flash_present = attribute('flash_present', default: false, description: 'Should we control presence of Adobe Flash hardening')

if flash_present
  title 'Adobe Flash'
  control 'flash-1' do
    impact 0.7
    title 'Flash management config file'
    desc 'Few security settings for flash'
    ref url: 'https://sverdis.com/hardening-flash-mission-impossible/'
    ref url: 'http://www.adobe.com/content/dam/Adobe/en/devnet/flashplayer/pdfs/flash_player_17_0_admin_guide.pdf'
    describe file('c:/Windows/SysWow64/Macromed/Flash/mms.cfg') do
      it { should be_file }
      its('content') { should match 'LocalFileReadDisable = 1' }
      its('content') { should match 'FileDownloadDisable = 1' }
      its('content') { should match 'FileUploadDisable = 1' }
      its('content') { should match 'DisableSockets = 1' }
      its('content') { should match 'ProtectedMode = 1' }
    end
  end
end
