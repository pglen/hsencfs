#  HSencFS

##  The High Security EnCrypting File System.


  Progress:

  ...  some working parts; almost ready to deploy

Announcements / History
    Tue 06.Jul.2021     dummy encryption is intercepted correctly
    Tue 06.Jul.2021     dummy encryption intercepted, working OK
    Tue 12.Apr.2022     started virtual based encryption (simpler algo)
    Tue 10.May.2022     real encryption operational

 HSENCFS is a user space encrypting file system. Simple to set up, seamless
to use, fast, safe, secure and maintenance free. It will encrypt
data on the fly written to it, decrypt data read from it. HSENCFS uses only
storage space for actual data stored, no pre-allocation needed. It is fast
enough for real time Video Encryption. HSENCFS is classified as a variable
key length encryption.

 An additional (and useful) feature is auditing. HSENCFS reports file access
by time and user ID. The report is sent to syslog. The log is sent to facility
'daemon' with level 'DEBUG'. See: the -l log option.)

 To use it (as a simple example):

      hsencfs  ~/secrets

 Will ask for password, and password creation confirmation if started on
a new mount. The above command exposes the ~/secrets directory with the
backing data directory in ~/.secrets

For added convenience, one may specify a dotted (hidden) file for mountdata.

      hsencfs  ~/secrets ~/.secrets

(in this example the storage dir becomes: ~/.secrets  (note the leading dot)

 You may un-mount your secret directory with the normal umount(8) utility
or the fusermount -u option. After un-mounting, the mounted data is not
accessible, and the encrypted data is not legible until it is mounted again.

(example: fusermount ~/secrets) The tilde '~' expands to the user's home dir.


## Password / Key management.

 HSENCFS does not manage passwords. The password becomes the encryption key,
and the key is used to encrypt the file system access. If the password / key
is lost, the data cannot be recovered. Seriously, the data is lost.

 As the password becomes the key, it is possible to achieve long key lengths
by entering a long password. Short key lengths are replicated to standard
legal length.

## On Demand Password entry:

 HSENCFS mount can be mounted (started) with the on-demand (-o) password
option. This allows the encryption to ask for a password when any
encrypted file is first accessed.

 The on-demand option requires the use of an ask-pass program. The
hsaskpass.py is supplied for GUI deployment. HSENCFS will start the ask-pass
program when a password is needed. This only truly makes sense on GUI
deployment, but the console program (hsaskpass) can also be specified.

An example of on-demand command line:

        hsencfs -o -a 'which hsaskpass.py` .mydata mysecret

Note the 'which' utility, as HSENCFS needs absolute path. In real deployment,
specify the askpass program's absolute path.

## Safety, Security

 HSENCFS uses BluePoint2 encryption. Bluepoint(2) has been thoroughly evaluated,
and withstood the test of time. The backing files in the data directory
preserve their original names, size, and access times. The only dependence
they need is the original password, and the .datx file. The files can be
safely copied from the backing directory for transport to other locations.
(for instance backup)

## Feeding and Care

  Please note that HSENCFS block size is 4096, and will handle data accordingly.
This was by choice, so encryption can be exceptionally strong.

### The data directory:

 Files can be extracted from the backing data directory. Just mount it, and copy the
files as usual.

## The cypher text.

 Files can be copied out from the backing data directory. They stay encrypted
when copied directly out of the backing/data directory. This is useful for backup /
replication / archiving / transport etc ... make sure you copy them with hidden
(.dot) files included. Use: shopt -s dotglob before copy. Warning: the
copied data will be unreadable without the dot files.

## Going to the Cloud.

 The backing data directory can reside on any valid file system, including
a cloud drive. HSENCFS will encrypt data automatically before the data sees
the transport layer, and decrypt data after the transport layer delivered it.
This makes hsencfs an end to end cipher, which allows secure remote storage
without data ever leaving the local context without encryption.

## The Mountpoint directory:

 When the mountpoint is mounted, data is encrypted / decrypted on the fly.
HSENCFS will warn you if the mount directory is not empty on mount. It is
usually undesirable to mount over data. You may force the mount, see FUSE
options for details.

### Configuring Shared Mountpoint(s):

 By default FUSE will not allow anyone (except the user) to see the mount. To
create a mount that is visible by others (on the same system) use the fuse
'allow_other' option. To append FUSE options, use '--' at the end of HSENCFS
command line. Fuse will not allow the allow_other option unless configured in
/etc/fuse.conf (add a line: 'user_allow_other')

 Example:
        hsencfs .mydata mymount -- -o allow_other

## Technical Description:

 HSENCFS makes use of the API offered by the fuse subsystem to intercept file
operations. The interception is done from mountdata to mountpoint. Placing
data to the mountpoint directory ends up encrypted in mountdata.
Because of HSENCFS intercept concept, encryption / decryption is fast.
It is plausible (and tested) to use it to encrypt video streams, or
compile programs in the encrypted directory.

### The GNOME Panel Applet: (unsupported)

 HSENCFS can be controlled from the GNOME Panel (System Tray) with the
hstray.py utility. New mounts can be added, mounted or unmounted. The mounts
are relative to the user's home directory unless an absolute path is specified.

 The 'comments' field can be used as a password hint. See PASSHINTS.

 Removing mounts from the hstray's list does not effect the data behind it.
The mounts created from the system tray are visible from the command line,
but the mounts created on the command line are not visible in the system
tray. (added protection)

 Upon panel install, the System Panel needs to rescan for the list of Applets for
the HSENCFS applet to show up. This can be achieved by adding an arbitrary
Applet to the panel, and then removing it. After the panel add / remove cycle,
the HSENCFS applet will show up.
 Naturally, one can force a rescan by restarting the gnome-panel or X-windows
or the whole system.

## Additional Versions:

 The industrial version of this project is available upon request.
Please send a message to the author. (see github page)

Useful trick to see the logs in a separate file.

Edit (Create) /etc/rsyslog/rsyslog.d/10-custom.conf
with the following contents:

if $programname == 'HSEncFs' then {
        /var/log/hsencfs.log
        ~
}

Then the file '/var/log/hsencfs.log' contains details of
the hsencfs workings. Use the -l option to control how much detail
would you like to see;

To copy every file including hidden ones (starting with a dot) use:

shopt -s dotglob

Assuming the following setup:

~/secrets       for the encrypted (user visible) directory
~/.secrets      for the supporting (data/storage) directory

One can copy plain files out:

1.) mount directory with hsencfs
2.) copy as usual

   example:  hsencfs ~/secret

One can copy encrypted files out:

        1.) the directory does not have to be mounted
        2.) enable copying all files; use: shopt -s dotglob
        2.) copy as usual

   example:  cp -a  ~/.secret/*  target_dir


Older Announcements:

     The source code copied out to the encrypted directory does NOT compile in that
    directory correctly.

    This means the file access intercept is not random clean,
    as GCC accesses object files by chunk.

     The trick was to pre read to the encryption buffer boundary, and then
      Decrypt / Patch / Encrypt / Write.

     The last buffer may be partial, so special arrangements are made to
    accommodate that.

  Thanks:

Peter Glen








// EOF
