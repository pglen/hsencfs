#!/usr/bin/env python

from __future__ import print_function

# GUI propmt for the user of HSENCFS

import os, sys, getopt, signal, base64

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository import Gdk

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

    label = Gtk.Label.new("Enter pass:  ");
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

# Start of program:
if __name__ == '__main__':

    prompt = ": ";  created = 0

    try:
        if sys.argv[1]:
            prompt = " for '" + sys.argv[1] + "' ";
    except:
        pass
    try:
        if sys.argv[2]:
            created = int(sys.argv[2])
    except:
        pass

    while 1:
        text, text2 = getpass( \
                "Enter HSENCFS Password%s" % prompt, created);
        if created:
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

    #print("text", "'" + text + "'")

    # Does not have to be rocket science ...
    # Just to hide from plaintext view:
    sss = base64.b64encode(text.encode())

    print(sss.decode())

# EOF
