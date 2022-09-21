# Security Policies

https://www.suse.com/c/applying-disa-stig-hardening-to-sles-installations/

The DISA ([Defense Information Systems Agency](https://disa.mil)) and SUSE have authored a STIG
(Secure Technical Implementation Guide) that describes how to harden a SUSE Linux Enterprise system.

The STIG is a long list of rules, each containing description, detection of problems and how to
remediate problems on a per rule basis.

While originally STIGs are supposed to applied manually, a large percentage of the rules can be and
were automated in so called SCAP format (Secure Content Automation Protocol).

We can classify rules into multiple cases:

* rules that need to be applied during installation of a system
* rules where remediation can be automatically applied after installation
* rules that are not able to be checked automatically nor remediated
* rules without automated remediation

## YaST and Security Policies

The YaST installer supports security policies. At this moment, the installer only offers the DISA
STIG policy, although more policies are expected to be added.

There are two ways for enabling security policies in YaST: in the Installation Summary dialog at
the end of the installation or by using the `YAST_SECURITY_POLICIES` boot parameter. Policies and
rules can also be enabled in the AutoYaST profile.

The Installation Summary has a Security Policy section that shows the policies and reports the
failing rules for the enabled policies. The policies are also checked by some YaST clients. For
example, the Guided Partitioning and the Expert Partitioner show the failing rules related to the
storage configuration. The installation will be blocked meanwhile there are failing rules.

In the Security Policy section, some rules offer a link to easily remediate the issue. For others
rules, the link will go to the proper installation client (e.g., the Storage Proposal) where the
user is expected to manually fix the security problem. Moreover, YaST allows disabling rules.
Disabled rules will not be checked by YaST and they will not blocked the installation. AutoYaST
profiles also support disabling rules.

## DISA STIG Checks

The YaST installer only checks a subset of the rules defined by a security policy. YaST is mainly
focused on such rules that need to be applied during the installation. For example, for DISA STIG
the following rules should be checked:

* [SLES-15-010330](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_encrypt_partitions]) All file systems are encrypted ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2022-06-06/finding/V-234831)).
* [SLES-15-040200](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_home) The system has a separate mount point for */home* ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2021-03-04/finding/V-235004)).
* [SLES-15-040210](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_var) The system has a separate mount point for */var* ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2021-06-14/finding/V-235005)).
* [SLES-15-040210](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_var_log_audit) The system has a separate file system for */var/log/audit* ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2022-06-06/finding/V-234980)).
* [SLES-15-030660](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_auditd_audispd_configure_sufficiently_large_partition) The file system /var/log/audit has enough capacity for audit records ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2022-06-06/finding/V-234965)).
* [SLES-15-010200](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_group_uefi) A bootloader password (for grub2) is configured (UEFI) ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2021-11-30/finding/V-234820)).
* [SLES-15-010190](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_group_non-uefi) A bootloader password (for grub2) is configured (BIOS) ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2022-02-11/finding/V-234819)).

Apart from the rules above, YaST also checks these other rules at installation time:

* [SLES-15-010220](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_service_firewalld_enabled) Firewalld is enabled ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2021-11-30/finding/V-234821)).
* [SLES-15-010380](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_wireless_disable_interfaces) Wireless Network Interfaces are deactivated ([stigviewer](https://www.stigviewer.com/stig/suse_linux_enterprise_server_15/2021-11-30/finding/V-234847)).


## YaST API

This section describes some implementation details of the security policies in YaST.

Everything related to security policies is defined under the `Y2Security::SecurityPolicies`
name space. Each policy is defined by its own class, for example
`Y2Security::SecurityPolicies::DisaStigPolicy`. The policy classes provide a `#failing_rules` method
which checks the policy rules and reports the failing rules. The rules are represented by instances
of a subclass of `Y2Security::SecurityPolicies::Rule`. Some rules are fixable, that is, they offer
a method for automatically fix the issue.

The security policies are managed by the singleton class `Y2Security::SecurityPolicies::Manager`.
That class provides an API for enabling and disabling policies and for getting the failing rules
from all the enabled policies. YaST clients (e.g., `Y2Security::Clients::SecurityPolicyProposal`)
use the policies manager to interact with the policies. In *yast-storage-ng*, the Guided Setup and
the Expert Partitoner also use the manager to get the failing rules related to the storage
configuration. The configuration to check by the policies can be configured with a
`Y2Security::SecurityPolicies::TargetConfig` object.

~~~ruby
#                 Manager
#                   |
#          _ _ _ _ _ _ _ _ _ _
#         |                   |
#         |                   |
#      Policy A            Policy B
#         |
#      _ _ _ _ _ _ _ _
#     |               |
#   rule1           rule2

require "y2security/security_policies"

manager = Y2Security::SecurityPolicies::Manager.instance

config = Y2Security::SecurityPolicies::TargetConfig.new

failing_rules = manager.failing_rules(config, scope: :network)
failing_rules.first.fixable?  #=> true
failing_rules.first.fix

policy = manager.find_policy(:disa_stig)
policy.rules.each(&:disable)
~~~
