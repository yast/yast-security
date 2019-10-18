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

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


Name:           yast2-security
Version:        4.2.5
Release:        0
Group:          System/YaST
License:        GPL-2.0-only
Summary:        YaST2 - Security Configuration
Url:            https://github.com/yast/yast-security

Source0:        %{name}-%{version}.tar.bz2

BuildRequires:  doxygen
BuildRequires:  pkg-config
BuildRequires:  perl-XML-Writer
BuildRequires:  update-desktop-files
BuildRequires:  yast2-pam
BuildRequires:  yast2-devtools >= 4.2.2
BuildRequires:  rubygem(%{rb_default_ruby_abi}:yast-rake) >= 0.2.5
BuildRequires:  rubygem(%{rb_default_ruby_abi}:rspec)
# Yast2::CFA::Sysctl
BuildRequires:  yast2 >= 4.2.25
# Unfortunately we cannot move this to macros.yast,
# bcond within macros are ignored by osc/OBS.
%bcond_with yast_run_ci_tests
%if %{with yast_run_ci_tests}
BuildRequires: rubygem(%{rb_default_ruby_abi}:yast-rake-ci)
%endif

# new Pam.ycp API
Requires:       yast2-pam >= 2.14.0
# CFA::Sysctl
Requires:       yast2 >= 4.2.25
Requires:       yast2-ruby-bindings >= 1.0.0

Provides:       y2c_sec yast2-config-security
Provides:       yast2-trans-security y2t_sec

Obsoletes:      y2c_sec yast2-config-security
Obsoletes:      yast2-trans-security y2t_sec

BuildArch:      noarch

%description
The YaST2 component for security settings configuration.

%prep
%setup -q

%build

%check
%yast_check

%install
%yast_install
%yast_metainfo

%post
# remove broken entry in /etc/login.defs, introduced during installation (bnc#807099)
if [ -f /etc/login.defs  ] ; then
  sed -e '/^[ \t]*LASTLOG_ENAB[ \t]*\"\"/d' -i /etc/login.defs
fi

%files
%{yast_yncludedir}
%{yast_desktopdir}
%{yast_metainfodir}
%{yast_clientdir}
%{yast_moduledir}
%{yast_scrconfdir}
%{yast_schemadir}
%{yast_ydatadir}
%{yast_libdir}
%{yast_icondir}
%doc %{yast_docdir}
%license COPYING

%changelog
