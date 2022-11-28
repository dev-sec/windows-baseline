# Changelog

## [2.1.10](https://github.com/dev-sec/windows-baseline/tree/2.1.10) (2022-11-28)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.9...2.1.10)

**Merged pull requests:**

- Always use HKEY\_LOCAL\_MACHINE\ when checking registry keys [\#64](https://github.com/dev-sec/windows-baseline/pull/64) ([spencer-cdw](https://github.com/spencer-cdw))

## [2.1.9](https://github.com/dev-sec/windows-baseline/tree/2.1.9) (2022-10-27)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.8...2.1.9)

**Implemented enhancements:**

- use centralised issue templates and workflows [\#62](https://github.com/dev-sec/windows-baseline/pull/62) ([schurzi](https://github.com/schurzi))

**Fixed bugs:**

- Error `undefined method `positive?' for #<RSpec::Matchers::DSL::Matcher cmp>` [\#59](https://github.com/dev-sec/windows-baseline/issues/59)
- Fix local\_policies 'no such value .positive?' [\#61](https://github.com/dev-sec/windows-baseline/pull/61) ([spencer-cdw](https://github.com/spencer-cdw))
- Revert lint breaking .positive [\#60](https://github.com/dev-sec/windows-baseline/pull/60) ([spencer-cdw](https://github.com/spencer-cdw))

**Merged pull requests:**

- Change linting to Cookstyle [\#58](https://github.com/dev-sec/windows-baseline/pull/58) ([schurzi](https://github.com/schurzi))

## [2.1.8](https://github.com/dev-sec/windows-baseline/tree/2.1.8) (2022-01-12)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.7...2.1.8)

**Merged pull requests:**

- Minimum requirements [\#57](https://github.com/dev-sec/windows-baseline/pull/57) ([micheelengronne](https://github.com/micheelengronne))
- fix rubocop error for Rakefile [\#53](https://github.com/dev-sec/windows-baseline/pull/53) ([schurzi](https://github.com/schurzi))
- add dependency to chef-config for CI [\#52](https://github.com/dev-sec/windows-baseline/pull/52) ([schurzi](https://github.com/schurzi))
- use version tag for changelog action [\#51](https://github.com/dev-sec/windows-baseline/pull/51) ([schurzi](https://github.com/schurzi))

## [2.1.7](https://github.com/dev-sec/windows-baseline/tree/2.1.7) (2021-01-29)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.6...2.1.7)

**Merged pull requests:**

- Fix lint [\#50](https://github.com/dev-sec/windows-baseline/pull/50) ([schurzi](https://github.com/schurzi))
- GitHub action [\#49](https://github.com/dev-sec/windows-baseline/pull/49) ([rndmh3ro](https://github.com/rndmh3ro))

## [2.1.6](https://github.com/dev-sec/windows-baseline/tree/2.1.6) (2020-08-07)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.5...2.1.6)

**Closed issues:**

- False Positives due to integers in strings [\#45](https://github.com/dev-sec/windows-baseline/issues/45)

**Merged pull requests:**

- Fixes comparisons when registry key data type are REG\_SZ [\#46](https://github.com/dev-sec/windows-baseline/pull/46) ([imjoseangel](https://github.com/imjoseangel))

## [2.1.5](https://github.com/dev-sec/windows-baseline/tree/2.1.5) (2020-07-23)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.4...2.1.5)

**Closed issues:**

- Typo FontBocking/FontBlocking? [\#35](https://github.com/dev-sec/windows-baseline/issues/35)

## [2.1.4](https://github.com/dev-sec/windows-baseline/tree/2.1.4) (2020-06-30)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.3...2.1.4)

**Fixed bugs:**

- Fixes SeIncreaseQuotaPrivilege [\#44](https://github.com/dev-sec/windows-baseline/pull/44) ([imjoseangel](https://github.com/imjoseangel))
- Fixes Readme copy and paste. Formats author table in readme [\#41](https://github.com/dev-sec/windows-baseline/pull/41) ([imjoseangel](https://github.com/imjoseangel))

**Closed issues:**

- copy / paste error in README.md [\#38](https://github.com/dev-sec/windows-baseline/issues/38)
- The 'should include' does not check for unwanted accounts [\#20](https://github.com/dev-sec/windows-baseline/issues/20)

## [2.1.3](https://github.com/dev-sec/windows-baseline/tree/2.1.3) (2020-06-18)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.2...2.1.3)

**Merged pull requests:**

- version alignment [\#40](https://github.com/dev-sec/windows-baseline/pull/40) ([micheelengronne](https://github.com/micheelengronne))

## [2.1.2](https://github.com/dev-sec/windows-baseline/tree/2.1.2) (2020-06-18)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.1...2.1.2)

**Closed issues:**

- formatting error when executing profile [\#34](https://github.com/dev-sec/windows-baseline/issues/34)
- LAN Manager authentication level incorrect [\#25](https://github.com/dev-sec/windows-baseline/issues/25)
- Should we close SeNetworkLogonRight for all users? [\#19](https://github.com/dev-sec/windows-baseline/issues/19)
- The title of each test should clearly state what should be done [\#18](https://github.com/dev-sec/windows-baseline/issues/18)

**Merged pull requests:**

- github actions release [\#39](https://github.com/dev-sec/windows-baseline/pull/39) ([micheelengronne](https://github.com/micheelengronne))
- replace the german text to english and fix the windows 2012r2 tag [\#37](https://github.com/dev-sec/windows-baseline/pull/37) ([atomic111](https://github.com/atomic111))
- Feature/inspec4alerts [\#33](https://github.com/dev-sec/windows-baseline/pull/33) ([imjoseangel](https://github.com/imjoseangel))

## [2.1.1](https://github.com/dev-sec/windows-baseline/tree/2.1.1) (2019-06-11)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.1.0...2.1.1)

**Merged pull requests:**

- Replace German characters to avoid exec failures and bump version to 2.1.1 [\#36](https://github.com/dev-sec/windows-baseline/pull/36) ([alexpop](https://github.com/alexpop))
- Update administrative\_templates\_computer.rb [\#32](https://github.com/dev-sec/windows-baseline/pull/32) ([Staggerlee011](https://github.com/Staggerlee011))
- fix missing "o" in windows-245 [\#31](https://github.com/dev-sec/windows-baseline/pull/31) ([rndmh3ro](https://github.com/rndmh3ro))

## [2.1.0](https://github.com/dev-sec/windows-baseline/tree/2.1.0) (2019-05-16)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/2.0.0...2.1.0)

**Merged pull requests:**

- Update gems and bump profile version to 2.1.0 [\#30](https://github.com/dev-sec/windows-baseline/pull/30) ([alexpop](https://github.com/alexpop))

## [2.0.0](https://github.com/dev-sec/windows-baseline/tree/2.0.0) (2019-05-15)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/1.2.0...2.0.0)

**Merged pull requests:**

- New windows cis profile for win2012r2 and 2016 [\#27](https://github.com/dev-sec/windows-baseline/pull/27) ([atomic111](https://github.com/atomic111))

## [1.2.0](https://github.com/dev-sec/windows-baseline/tree/1.2.0) (2019-05-15)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/1.1.2...1.2.0)

**Merged pull requests:**

- correct license style and bump version to 1.1.3 [\#28](https://github.com/dev-sec/windows-baseline/pull/28) ([atomic111](https://github.com/atomic111))
- Update common [\#26](https://github.com/dev-sec/windows-baseline/pull/26) ([atomic111](https://github.com/atomic111))
- Update issue templates [\#24](https://github.com/dev-sec/windows-baseline/pull/24) ([rndmh3ro](https://github.com/rndmh3ro))
- fixing control for 'cis-access-cred-manager-2.2.1' [\#23](https://github.com/dev-sec/windows-baseline/pull/23) ([wer-sce](https://github.com/wer-sce))

## [1.1.2](https://github.com/dev-sec/windows-baseline/tree/1.1.2) (2019-03-26)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/1.1.0...1.1.2)

**Closed issues:**

- boolean 'or' logic for describe block [\#21](https://github.com/dev-sec/windows-baseline/issues/21)

**Merged pull requests:**

- Fixed spelling error [\#17](https://github.com/dev-sec/windows-baseline/pull/17) ([hannah-radish](https://github.com/hannah-radish))
- Move SMB1 control to windows-baseline [\#16](https://github.com/dev-sec/windows-baseline/pull/16) ([yvovandoorn](https://github.com/yvovandoorn))

## [1.1.0](https://github.com/dev-sec/windows-baseline/tree/1.1.0) (2017-05-08)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/1.0.1...1.1.0)

**Implemented enhancements:**

- The baseline should be organized by components [\#6](https://github.com/dev-sec/windows-baseline/issues/6)

**Closed issues:**

- Licensing information mismatch? [\#4](https://github.com/dev-sec/windows-baseline/issues/4)

**Merged pull requests:**

- update metadata [\#15](https://github.com/dev-sec/windows-baseline/pull/15) ([chris-rock](https://github.com/chris-rock))
- Privacy [\#13](https://github.com/dev-sec/windows-baseline/pull/13) ([MattTunny](https://github.com/MattTunny))
- add cis tags for some controls [\#12](https://github.com/dev-sec/windows-baseline/pull/12) ([chris-rock](https://github.com/chris-rock))
- add references to powershell hardening [\#11](https://github.com/dev-sec/windows-baseline/pull/11) ([chris-rock](https://github.com/chris-rock))
- restrict ruby testing in travis to 2.3.3 [\#10](https://github.com/dev-sec/windows-baseline/pull/10) ([chris-rock](https://github.com/chris-rock))
- added powershell test [\#9](https://github.com/dev-sec/windows-baseline/pull/9) ([MattTunny](https://github.com/MattTunny))
- rename controls [\#8](https://github.com/dev-sec/windows-baseline/pull/8) ([chris-rock](https://github.com/chris-rock))
- add contribution guidelines [\#7](https://github.com/dev-sec/windows-baseline/pull/7) ([chris-rock](https://github.com/chris-rock))

## [1.0.1](https://github.com/dev-sec/windows-baseline/tree/1.0.1) (2017-02-01)

[Full Changelog](https://github.com/dev-sec/windows-baseline/compare/5b20a47a9d7ce334d28800aa5719e5bf83fd3898...1.0.1)

**Merged pull requests:**

- Removed per control licensing as repo is under Apache 2.0 [\#5](https://github.com/dev-sec/windows-baseline/pull/5) ([grdnrio](https://github.com/grdnrio))
- 1.0.0 [\#3](https://github.com/dev-sec/windows-baseline/pull/3) ([chris-rock](https://github.com/chris-rock))
- Switched fron Nil to Nobody SID due to mismatch on 2012R2 [\#2](https://github.com/dev-sec/windows-baseline/pull/2) ([grdnrio](https://github.com/grdnrio))
- Joeg/sid refactor [\#1](https://github.com/dev-sec/windows-baseline/pull/1) ([grdnrio](https://github.com/grdnrio))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
