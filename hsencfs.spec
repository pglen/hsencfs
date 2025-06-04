Name:           hsencfs
Version:        1.5.0
Release:        2
Summary:        High Security Encrypted File System
Maintainer:	    peterglen99@gmail.com
Group:          Encryption
License:        GPL
URL:            http://www.sourceforge.net
Source0:        hsencfs-1.5.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  fuse3 ssl crypto
Requires:       fuse3 ssl crypto
%description
 HSENCFS is a user space encrypting file system. Simple to set up, seamless  \
to use, fast, safe, secure and maintenance free. It will seamlessly encrypt  \
data written to it, decrypt data read from it. It only uses storage space    \
for actual data stored, no pre-allocation needed. It is fast enough for real \
time video encryption. HSENCFS is classified as a variable key length  \
encryption.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%pre

%post
# removed panel specific code
# Panel will look for the server file /usr/lib/bonobo
# Patch server.in to accomodate
#echo "Post process: creating bonobo server file"
#cat %_docdir/hsencfs/GNOME_HSENCApplet.server.in | \
#  sed s%HSTRAY_BIN%/usr/bin/hstray.py% \
#        > /usr/lib/bonobo/servers/GNOME_HSENCApplet.server
#echo "Post process done"

%preun

%postun
#rm -f /usr/lib/bonobo/servers/GNOME_HSENCApplet.server

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%_bindir/bpdec2
%_bindir/bpenc2
%_bindir/hsaskpass
%_bindir/hsaskpass.py
%_bindir/hsencfs
%_bindir/hstray.py
%_docdir/hsencfs/FUSEOPTS
%_docdir/hsencfs/PASSES
%_docdir/hsencfs/QUICKSTART
%_docdir/hsencfs/SECURITY
%_docdir/hsencfs/hsencfs.init
%_docdir/hsencfs/hsencfs.spec
%_docdir/hsencfs/hsencfs.spec
%_docdir/hsencfs/GNOME_HSENCApplet.server.in
%_infodir/hsencfs.info.gz
%_datadir/pixmaps/hspadlock.png
%_datadir/pixmaps/hsicon.png
%_mandir/man1/hsencfs.1.gz

%doc

%changelog

* Sun Sep 08 2019 Peter Glen
- Recompile on 64 bit Fedora, github initial

* Sat Jun 06 2015 Peter Glen
- Initial Release

* Thu Jun 04 2015 Peter Glen
- hsenc-016

* Sat May 30 2015 Peter Glen
- hsenc-015

* Tue May 12 2015 Peter Glen
- hsenc-001














