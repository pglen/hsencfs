#!/usr/bin/env python

# GUI propmt for the user of HSENCFS

import os, sys, getopt, signal
import gobject, gtk

def getpass(title, message):

    dialog = gtk.Dialog(title,
                   None,
                   gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT)

    sp = "   "
    try:
        dialog.set_icon_from_file("hsicon.png")
    except:
        try:
            dialog.set_icon_from_file( \
                "/usr/local/share/icons/hsencfs/hsicon.png")
        except:                                              
            pass
    
    label = gtk.Label(message); 
    label2 = gtk.Label(sp);     label3 = gtk.Label(sp)
    hbox = gtk.HBox() ;         hbox.pack_start(label2);  
    hbox.pack_start(label);     hbox.pack_start(label3)
    
    entry = gtk.Entry();    
    entry.set_invisible_char("*")
    entry.set_visibility(False)
    
    entry.set_width_chars(64)
    
    label21 = gtk.Label(sp);     label31 = gtk.Label(sp)
    hbox.pack_start(label21);     
    hbox.pack_start(entry)
    hbox.pack_start(label31)
    
    label22 = gtk.Label(sp);     label32 = gtk.Label(sp)
    
    dialog.vbox.pack_start(label22)
    dialog.vbox.pack_start(hbox)
    dialog.vbox.pack_start(label32)

    #dialog.set_default_response(gtk.RESPONSE_YES)
    entry.set_activates_default(True)
    
    dialog.add_button("_OK", gtk.RESPONSE_YES)
    dialog.add_button("_Cancel", gtk.RESPONSE_NO)
    
    dialog.connect("key-press-event", area_key)
    dialog.show_all()
    response = dialog.run() 
    text = entry.get_text()
                
    # Convert all responses to cancel
    if  response == gtk.RESPONSE_CANCEL or \
        response == gtk.RESPONSE_REJECT or \
        response == gtk.RESPONSE_CLOSE  or \
        response == gtk.RESPONSE_DELETE_EVENT:
        response = gtk.RESPONSE_CANCEL        
    dialog.destroy()
    
    if response != gtk.RESPONSE_CANCEL:
        return  text
    else: 
        return ""

def area_key(win, event):

    if event.keyval == gtk.keysyms.Return:
        win.response(gtk.RESPONSE_OK)

# Start of program:
if __name__ == '__main__':

    text = getpass("Enter HSENCFS Password", "Enter pass: ");    
    print text



