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

The YaST installer supports security policies which can be enabled in the Installation Summary. The
installer checks the rules of the enabled policies and reports the issues to fix before proceeding
with the installation. For some issues, YaST offers a link to easily remediate it. For others, the
link will take you to the proper installation client to fix the issue (e.g., the Guided
Partitoning). At this moment, only the DISA STIG policy is supported, but the YaST infrastructure
is ready to offer more policies if requested.

The boot parameter `YAST_SECURITY_POLICIES` can be used for enabling policies from the beginning of
the installation without waiting until reaching the Installation Summary. If the policies are
enabled (e.g., `YAST_SECURITY_POLICIES=disa_stig`), then some YaST clients could show policies
issues too. For example, the Guided Partitioning client and the Expert Partitioner show the policies
issues related to storage configuration.

## DISA STIG Checks

The YaST installer only checks a subset of the rules defined by a security policy. YaST is mainly
focused on such rules that need to be applied during the installation. For example, for DISA STIG
the following rules should be checked:

* All file systems are encrypted ([SLES-15-010330](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_encrypt_partitions])).
* The system has a separate mount point for */home* ([SLES-15-040200](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_home)).
* The system has a separate mount point for */var* ([SLES-15-040210](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_var)).
* The system has a separate mount point for */var/log/audit* ([SLES-15-040210](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_partition_for_var_log_audit)) (Note: this rule is not checked by YaST).
* A bootloader password (for grub2) must be configured (UEFI) ([SLES-15-010200](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_group_uefi)).
* A bootloader password (for grub2) must be configured (non-UEFI) ([SLES-15-010190](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_group_non-uefi)) (Note: this rule is not checked by YaST).

Apart from the rules above, YaST also checks these other rules at installation time:

* Verify firewalld is enabled ([SLES-15-010220](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_service_firewalld_enabled)).
* Deactivate Wireless Network Interfaces ([SLES-15-010380](http://static.open-scap.org/ssg-guides/ssg-sle15-guide-stig.html#xccdf_org.ssgproject.content_rule_wireless_disable_interfaces)).


## YaST API

This section describes some implementation details of the security policies in YaST.

Everything related to security policies is defined under the `Y2Security::SecurityPolicies`
namespace. Each policy is defined by its own class, for example
`Y2Security::SecurityPolicies::DisaStigPolicy`. The policy classes provide a `#validate` method
which checks the policy rules and reports a list of issues. The issues are represented by instances
of the `Y2Security::SecurityPolicies::Issue` class. An issue optionally has an associated action
(`Y2Security::SecurityPolicies::Action`) to automataically fix the issue.

The security policies are managed by the singleton class `Y2Security::SecurityPolicies::Manager`.
That class offers an API for enabling and disabling policies and for getting the issues from all the
enabled policies. YaST clients use the policies manager to interact with the policies. For example,
`Y2Security::Clients::SecurityPolicyProposal` uses the manager to enable and disable policices and
to get the list of issues. In *yast-storage-ng*, the Guided Setup and the Expert Partitoner also use
the manager to get the list of storage issues. Scopes are used for limiting the policy checks to a
specific area (e.g., storage). The scopes are defined under the
`Y2Security::SecurityPolicies::Scopes` namespace.

~~~
            Manager
              |
     _ _ _ _ _ _ _ _ _ _
    |                   |
(enabled)           (disabled)
    |                   |
 PolicyA             PolicyB
    |
 _ _ _ _ _ _ _ _
|               |
issue(#fix)     issue
~~~
