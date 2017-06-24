[![Build Status](https://travis-ci.org/juju4/windows-baseline.svg?branch=master)](https://travis-ci.org/juju4/windows-baseline)
windows-baseline
================

This Baseline ensures, that all hardening projects keep the same quality.

- https://github.com/dev-sec/chef-windows-hardening

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/dev-sec/windows-baseline
$ inspec exec windows-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/dev-sec/windows-baseline

# run test on remote windows host on WinRM
$ inspec exec test.rb -t winrm://Administrator@windowshost --password 'your-password'
```

## License and Author

* Copyright 2015-2016, Chef Software, Inc
* Copyright 2016, The Hardening Framework Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
