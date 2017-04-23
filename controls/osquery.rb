# encoding: utf-8

title 'Facebook Osquery'

control 'osquery-1' do
  impact 0.7
  title 'Osqueryd is running'
  desc 'Osqueryd is active'
  ## FIXME! check process path
  describe processes('osqueryd.exe') do
    #describe processes('c:\ProgramData\osquery\osqueryd.exe') do
    its('list.length') { should eq 1 }
  end
  describe file('c:\ProgramData\osquery\osquery.conf') do
    it { should be_file }
  end
end

