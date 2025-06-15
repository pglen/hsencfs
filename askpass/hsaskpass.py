#!/usr/bin/env python

from __future__ import print_function

# GUI propmt for the user of HSENCFS

import os, sys, getopt, signal, base64, syslog, time
import argparse

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository import Gdk

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def hslog(lev, *xargs):

    #print("hslog:", lev, *xargs)

    # Do not turn on unless want to see details
    if not args.loglevel:
        return

    if lev <= args.loglevel:
        sumx = ""
        for aa in xargs:
            sumx += str(aa) + " "
        syslog.syslog(sumx)

def message_dialog(strx, header = "Message Dialog" ):

    dialog = Gtk.MessageDialog()
    dialog.set_title(header);
    dialog.set_markup(strx);
    dialog.add_button("_OK",  Gtk.ResponseType.OK)
    res = dialog.run()
    dialog.destroy()
    return res

class xEntry(Gtk.Entry):

    def __init__(self, form, action = None):
        super(xEntry, self).__init__()
        self.form = form
        self.action = action
        self.connect("activate", self.enterkey)
        self.connect("focus-out-event", self.focus_out)
        #pass

    def focus_out(self, arg, foc):
        #print("Focus out", arg, foc)
        self.select_region(0,0)

    def enterkey(self, arg):
        #print("Enter:", self.get_text())
        if self.action:
            ret = self.action(self)
            if not ret:
                self.form.child_focus(Gtk.DirectionType.TAB_FORWARD)
        else:
            self.form.child_focus(Gtk.DirectionType.TAB_FORWARD)
        return True

def precheck_pass(self):
    #print("precheck pass", self)
    pass

def postcheck_pass(self):
    #print("postcheck pass", self)
    pass

def getpass(title, crflag):

    global dialog
    dialog = Gtk.Dialog(title,   None, modal = True, destroy_with_parent = True)
    #Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT)

    try:
        dialog.set_icon_from_file("hsicon.png")
    except:
        try:
            dialog.set_icon_from_file( \
                "/usr/local/share/icons/hsencfs/hsicon.png")
        except:
            pass

    grid = Gtk.Grid()

    label = Gtk.Label.new("  ");
    grid.attach(label, 1, 0, 1, 1)

    label = Gtk.Label.new(args.prompt);
    grid.attach(label, 0, 1, 1, 1)

    entry = xEntry(dialog, precheck_pass)
    entry.set_invisible_char("*")
    entry.set_visibility(False)
    entry.set_width_chars(64)
    grid.attach(entry, 1, 1, 1, 1)

    label = Gtk.Label.new("  ");
    grid.attach(label, 1, 2, 1, 1)

    entry2 = xEntry(dialog, postcheck_pass);

    # Second row
    if crflag:

        labelj = Gtk.Label.new(" This is a new mount, please verify password.");
        labelj.set_xalign(0)
        #labelj.override_background_color(Gtk.StateType.NORMAL,
        #                Gdk.RGBA(.5, .5, .5, 1))
        grid.attach(labelj, 1, 3, 1, 1)
        grid.attach(Gtk.Label.new("  "), 1, 4, 1, 1)

        label = Gtk.Label.new("Verify:  ");
        grid.attach(label, 0, 6, 1, 1)

        #entry2 = xEntry(dialog);
        entry2.set_invisible_char("*")
        entry2.set_visibility(False)
        entry2.set_width_chars(64)
        grid.attach(entry2, 1, 6, 1, 1)

        label = Gtk.Label.new("  ")
        grid.attach(label, 1, 6, 1, 1)

        label2 = Gtk.Label.new("  ");
        grid.attach(label2, 1, 7, 1, 1)
        entry2.set_activates_default(True)
    else:
        entry.set_activates_default(True)

    hbox = Gtk.HBox()
    hbox.pack_start(Gtk.Label.new("      "), 0, 0, 0)
    hbox.pack_start(grid, 0, 0, 0)
    hbox.pack_start(Gtk.Label.new("      "), 0, 0, 0)

    dialog.vbox.pack_start(hbox, 0, 0, 0)

    #dialog.set_default_response(Gtk.ResponseType.YES)

    dialog.add_button("_OK", Gtk.ResponseType.YES)
    dialog.add_button("_Cancel", Gtk.ResponseType.NO)

    dialog.connect("key-press-event", area_key, crflag)
    dialog.show_all()
    response = dialog.run()
    text = entry.get_text()
    text2 = entry2.get_text()

    # Convert all responses to cancel
    if  response == Gtk.ResponseType.CANCEL or \
        response == Gtk.ResponseType.REJECT or \
        response == Gtk.ResponseType.CLOSE  or \
        response == Gtk.ResponseType.DELETE_EVENT:
        response = Gtk.ResponseType.CANCEL
    dialog.destroy()

    if response != Gtk.ResponseType.CANCEL:
        return  text, text2
    else:
        return None, None

def area_key(win, event, crflag):
    pass
    #if crflag:
    #    if event.keyval == Gdk.KEY_Return:
    #        win.response(Gtk.ResponseType.OK)

Version = "1.0.0"
pdesc = 'HSENCFS password GUI. '
pform = "Use TAB or enter to navigate between fields.\n" \
        "Press enter key to submit.\n" \
        "Use single or double quotes to group fields."

def parseargs():

    parser = argparse.ArgumentParser( description=pdesc, epilog=pform)

    parser.add_argument("-V", '--version', dest='version',
                        default=0,  action='store_true',
                        help='Show version number.')


    parser.add_argument("-v", '--verbose', dest='verbose',
                        default=0,  action='count',
                        help='Verbose level. Repeat -v for more verbossity.')

    parser.add_argument("-l", '--loglevel', dest='loglevel', type=int,
                        default=0,  action='store',
                        help='Log level to syslog. Value: 0-10. Default: 0')

    parser.add_argument("-p", '--prompt', dest='prompt', type=str,
                        default="  Enter Pass:  ",  action='store',
                        help='Prompt line left of pass string.')

    parser.add_argument("-t", '--title', dest='title', type=str,
                        default="HSENCFS password",  action='store',
                        help='Window title, for HSENCFS path.')

    parser.add_argument("-k", '--pubkey', dest='pubkey', type=str,
                        default="",  action='store',
                        help='Public key for encrypting results.')

    parser.add_argument("-c", '--create', dest='create', type=int,
                        default=0,  action='store',
                        help='Creation flag to double pass prompt.')
    return parser

def mainloop():

    global args

    parser = parseargs()
    args = parser.parse_args()
    #print(args)

    if args.version:
        print("Version: %s" % Version)
        #print("Crypto Version: %s" % Crypt)
        #self.OnExit(0)
        sys.exit(0)

    hslog(1, "Started hsakpass.py", args.prompt)

    if args.verbose:
        print("prompt:", args.prompt)
        print("created:", args.create)
        print("pubkey:", args.pubkey)

    star = " "
    if args.pubkey:
        star = "*"
    head = "%s Mounting: '%s'" % (star, args.title);
    while 1:
        text, text2 = getpass(head, args.create)
        if args.create:
            # Compare
            #print("comparing:", text, text2)
            if text == None:
                text = ""
                break
            elif text == "":
                message_dialog("No empty passwords allowed.", "Passwords Message")
            elif text == text2:
                break
            else:
                message_dialog("Passwords do not match.", "Passwords Message")
        else:
            if text == None:
                text = ""
            break

    # Does not have to be rocket science ...
    # Just to hide from plaintext view:
    #print(sss.decode())
    #print(enc_text)

    # Turns out rocket science is needed
    # Create pub key from str:
    if args.pubkey:
        try:
            mykey = RSA.import_key(args.pubkey)
            hslog(2, "mykey", mykey)
        except:
            text = str(sys.exc_info())
            #print(text)
            sss = base64.b64encode(text.encode())
            print(sss.decode(), end = "")
            hslog(1, "Cannot create key: '%s'." % args.pubkey)
            mykey = None
            sys.exit(1)

        cipher_rsa = PKCS1_OAEP.new(mykey)
        ksize = mykey.size_in_bytes()
        hslog(1, "keysize", ksize)
        enc_text = cipher_rsa.encrypt(text.encode())
        hslog(4, "enc_text", enc_text)
        sss = base64.b64encode(enc_text)
    else:
        sss = base64.b64encode(text.encode())
    print(sss.decode(), end = "")

# Start of program:
if __name__ == '__main__':
    try:
        mainloop()
    except SystemExit as xcode:
        sys.exit(xcode)
    except:
        hslog(1, "Exception: " , sys.exc_info())
        #print("mainloop exception: ", sys.exc_info())
        raise
        pass
# EOF
