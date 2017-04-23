# encoding: utf-8

title 'Ms EMET'

control 'EMET-1' do
  impact 0.7
  title 'Ms EMET is running'
  desc 'EMET process monitoring is active'
  describe processes('EMET_Service.exe') do
    its('list.length') { should eq 1 }
    its('users') { should cmp 'SYSTEM' }
  end
  describe processes('EMET_Agent.exe') do
    its('list.length') { should eq 1 }
  end
end
