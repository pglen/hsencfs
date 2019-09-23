#!/usr/bin/env python

from __future__ import print_function

# GUI propmt for the user of HSENCFS

import os, sys, getopt, signal, base64

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository import Gdk

def getpass(title, message):

    dialog = Gtk.Dialog(title,
                   None,
                   Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT)

    sp = "   "
    try:
        dialog.set_icon_from_file("hsicon.png")
    except:
        try:
            dialog.set_icon_from_file( \
                "/usr/local/share/icons/hsencfs/hsicon.png")
        except:
            pass

    label = Gtk.Label(message);
    label2 = Gtk.Label(sp);     label3 = Gtk.Label(sp)
    hbox = Gtk.HBox() ;         hbox.pack_start(label2, 0, 0, 0)
    hbox.pack_start(label, 0, 0, 0);     hbox.pack_start(label3, 0, 0, 0)

    entry = Gtk.Entry();
    entry.set_invisible_char("*")
    entry.set_visibility(False)

    entry.set_width_chars(64)

    label21 = Gtk.Label(sp);     label31 = Gtk.Label(sp)
    hbox.pack_start(label21, 0, 0, 0);
    hbox.pack_start(entry, 0, 0, 0)
    hbox.pack_start(label31, 0, 0, 0)

    label22 = Gtk.Label(sp);     label32 = Gtk.Label(sp)

    dialog.vbox.pack_start(label22, 0, 0, 0)
    dialog.vbox.pack_start(hbox, 0, 0, 0)
    dialog.vbox.pack_start(label32, 0, 0, 0)

    #dialog.set_default_response(Gtk.ResponseType.YES)
    entry.set_activates_default(True)

    dialog.add_button("_OK", Gtk.ResponseType.YES)
    dialog.add_button("_Cancel", Gtk.ResponseType.NO)

    dialog.connect("key-press-event", area_key)
    dialog.show_all()
    response = dialog.run()
    text = entry.get_text()

    # Convert all responses to cancel
    if  response == Gtk.ResponseType.CANCEL or \
        response == Gtk.ResponseType.REJECT or \
        response == Gtk.ResponseType.CLOSE  or \
        response == Gtk.ResponseType.DELETE_EVENT:
        response = Gtk.ResponseType.CANCEL
    dialog.destroy()

    if response != Gtk.ResponseType.CANCEL:
        return  text
    else:
        return ""

def area_key(win, event):

    if event.keyval == Gdk.KEY_Return:
        win.response(Gtk.ResponseType.OK)

# Start of program:
if __name__ == '__main__':

    text = getpass("Enter HSENCFS Password", "Enter pass: ");

    # Does not have to be rocket science, just to hide from plaintext view:

    print(base64.b64encode(text))




