# windows-baseline

[![Build Status](http://img.shields.io/travis/dev-sec/windows-baseline.svg)](http://travis-ci.org/dev-sec/windows-baseline)
[![Supermarket](https://img.shields.io/badge/InSpec%20Profile-Windows%20Baseline-brightgreen.svg)](https://supermarket.chef.io/tools/windows-baseline)

This Baseline ensures, that all hardening projects keep the same quality.

- https://github.com/dev-sec/chef-windows-hardening
- https://github.com/dev-sec/ansible-windows-hardening

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile is inspired by [CIS](https://downloads.cisecurity.org/) Windows 2012R2 and 2016 Benchmark and implements such rules in an automated way to provide security best-practice tests around Windows Servers in a production environment.

__Implements:__

* CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018
* CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

* at least [InSpec](http://inspec.io/) Version 3.0.0
* WinRM activated (for inspec remote usage)

### Platform

- Windows 2012R2
- Windows 2016
- Windows 2019

## Attributes

We use a yml attribute file to steer the configuration, the following options are available:

  * `level_1_or_2`
    define which CIS Benchmark Level (1 or 2) you want to execute

  * `ms_or_dc`
    define if you want to execute the profile in the context of a Memeber Server (MS) or Domain Controler (DC)

  * `password_history_size`
    define password history size

  * `maximum_password_age`
    define MaximumPasswordAge

  * `se_network_logon_right`
    define which users are allowed to access this computer from the network

  * `se_interactive_logon_right`
    define which users are allowed to log on locally

  * `se_remote_interactive_logon_right`
    define which users are allowed to log on through Remote Desktop Services

  * `se_backup_privilege`
    define which users are allowed to backup files and directories

  * `se_systemtime_privilege`
    define which users are allowed to change system time

  * `se_time_zone_privilege`
    define which users are allowed to change system time zone

  * `se_create_symbolic_link_privilege`
    define which users are allowed to create symbolic links

  * `se_deny_network_logon_right`
    define which users are not allowed to access this computer from the network

  * `se_deny_remote_interactive_logon_right`
    define which users are not allowed to log on through Remote Desktop Services

  * `se_enable_delegation_privilege`
    define which users are allowed to enable computer and user accounts to be trusted

  * `se_impersonate_privilege`
    define which users are allowed to impersonate a client after authentication

  * `se_load_driver_privilege`
    define which users are allowed to load and unload device drivers

  * `se_batch_logon_right`
    define which users are allowed to log on as a batch job

  * `se_security_privilege`
    define which users are allowed to manage auditing and security logs

  * `se_assign_primary_token_privilege`
    define which users are allowed to replace a process level token

  * `se_restore_privilege`
    define which users are allowed to restore files and directories

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```
# run profile locally and directly from Github
$ inspec exec https://github.com/dev-sec/windows-baseline

# run profile locally
$ git clone https://github.com/dev-sec/windows-baseline
$ inspec exec windows-baseline

# run profile on remote host via WinRM
inspec exec windows-baseline -t winrm://<ip-address>:5985 --user=<username> --password=<password>

# run profile on remote host via WinRM and define attribute value
inspec exec windows-baseline -t winrm://<ip-address>:5985 --user=<username> --password=<password> --attrs sample_attributes.yml

# run profile direct from inspec supermarket
inspec supermarket exec dev-sec/windows-baseline -t winrm://<ip-address>:5985 --user=<username> --password=<password>
```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```
inspec exec windows-baseline --controls 'windows-001'
```

## ToDo

- adjust the inspec attributes according to the profile (Member Server or Domain Controller), because for the Domain Controller some attributes are different from a Memeber Server

## Contributors + Kudos

* Patrick Muench [atomic111](https://github.com/atomic111)
* Torsten Löbner [TLoebner](https://github.com/TLoebner)
* Karsten Mueller [karstenmueller](https://github.com/karstenmueller)

## License and Author

|                |                                               |
|----------------|-----------------------------------------------|
| **Author:**    | Patrick Muench <patrick.muench1111@gmail.com> |
| **Author:**    | Torsten Loebner <loebnert@googlemail.com>     |
| **Copyright:** | 2019 SVA System Vertrieb Alexander GmbH       |
| **Copyright:** | 2019 Lichtblick SE                            |
| **Copyright:** | 2015-2016, Chef Software, Inc                 |
| **Copyright:** | DevSec Hardening Framework Team               |
| **License:**   | Apache License Version 2.0                    |
