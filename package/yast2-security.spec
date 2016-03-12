#
# spec file for package yast2-security
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-security
Version:        3.2.2
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:          System/YaST
License:        GPL-2.0
BuildRequires:  doxygen pkg-config perl-XML-Writer update-desktop-files yast2-pam
BuildRequires:  yast2-devtools >= 3.1.10
BuildRequires:  yast2-mail
BuildRequires:  rubygem(yast-rake) >= 0.2.5
BuildRequires:  rubygem(rspec)
# Directory.find_data_file
BuildRequires:  yast2 >= yast2-3.1.131

# new Pam.ycp API
Requires:       yast2-pam >= 2.14.0

# etc_sysctl_conf.scr
# Wizard::SetDesktopTitleAndIcon
# Directory.find_data_file
Requires:       yast2 >= yast2-3.1.131

Provides:       y2c_sec yast2-config-security
Obsoletes:      y2c_sec yast2-config-security
Provides:       yast2-trans-security y2t_sec
Obsoletes:      yast2-trans-security y2t_sec

BuildArchitectures: noarch

Requires:       yast2-ruby-bindings >= 1.0.0

Summary:        YaST2 - Security Configuration

%description
The YaST2 component for security settings configuration.

%prep
%setup -n %{name}-%{version}

%build

%check
%yast_check

%install
%yast_install


%post
# remove broken entry in /etc/login.defs, introduced during installation (bnc#807099)
if [ -f /etc/login.defs  ] ; then
  sed -e '/^[ \t]*LASTLOG_ENAB[ \t]*\"\"/d' -i /etc/login.defs
fi

%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/security
%{yast_yncludedir}/security/*
%{yast_desktopdir}/security.desktop
%{yast_clientdir}/security*.rb
%{yast_moduledir}/Security.rb
%{yast_scrconfdir}/*.scr
%{yast_schemadir}/autoyast/rnc/security.rnc
%{yast_ydatadir}/security
%{yast_libdir}/security
%doc %{yast_docdir}
