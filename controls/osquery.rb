# encoding: utf-8

osquery_present = attribute('osquery_present', default: false, description: 'Should we control presence of Facebook osquery')

if osquery_present?
  title 'Facebook Osquery'

  control 'osquery-1' do
    impact 0.7
    title 'Osqueryd is running'
    desc 'Osqueryd is active'
    ref url: 'https://www.facebook.com/notes/protect-the-graph/introducing-osquery-for-windows/1775110322729111'
    # describe processes('osqueryd.exe') do
    # describe processes('c:\ProgramData\osquery\osqueryd.exe') do
    #   its('list.length') { should eq 1 }
    # end
    describe file('c:\ProgramData\osquery\osquery.conf') do
      it { should be_file }
    end
  end
end
