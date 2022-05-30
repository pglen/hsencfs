#!/usr/bin/python
# -*- coding: UTF-8 -*-

# System Tray -- for High Security Encrypting File System. Supply the 
# 'window' command line for making a test run as a regular window.
# Note that the GUI subsystem is not interacting with entries 
# you start from the command line. May or may not be what you want,
# so be aware. (security / convenience tradeoff)

import warnings

warnings.simplefilter("ignore", Warning)
warnings.simplefilter("ignore", DeprecationWarning)

import time, sys, subprocess
import os, string, re, traceback
import sqlite3, syslog

import gnome.ui, gtk, gobject
import pygtk;  pygtk.require('2.0')

#warnings.simplefilter("default", Warning)
        
try:
    import gnomeapplet
except ImportError:
    import gnome.applet
    gnomeapplet = gnome.applet

# ------------------------------------------------------------------------

traydbname = "traydb"
imgname =   "/usr/local/share/pixmaps/hspadlock.png" 
imgname2 =  "/usr/share/pixmaps/hspadlock.png" 
logfile = None

# ------------------------------------------------------------------------
# Resolve path name

def respath(fname):
    ppp = string.split(os.environ['PATH'], os.pathsep)
    for aa in ppp:
        ttt = aa + os.sep + fname
        #print ttt
        if os.path.isfile(ttt):
            return ttt

# ------------------------------------------------------------------------
# Return tuple of exe's (stdout, stderr)

def mountitem(ondem, xsel, xmnt, xopt):

    pexec = respath("hsaskpass.py")
    if pexec == None:
        return None, "Please install 'hsaskpass.py' first"
    phsenc = respath("hsencfs")
    if phsenc == None:
        return None, "Please install 'hsencfs' first"
        
    args = [phsenc, ondem, "-a", pexec, xsel, xmnt]
    # Add options, prefix them with -o
    args.append("--")
    if xopt != "":
        for aa in string.split(xopt, " "):
            args.append("-o")
            args.append(aa)
    # Make a visible name
    args.append("-o")    
    args.append("fsname=" + os.path.basename(xsel))
    #print "args to subprocess:", args
    output = ("", "")
    try:
        output = subprocess.Popen(args, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
    except:
        #print "Cannot execute: " + args[0], sys.exc_info()
        return None, "Cannot execute: " + args[0] + " " + \
                     str(sys.exc_info()[1])
    #print "output", output
    return output

# ------------------------------------------------------------------------
#
def is_mounted(sel):
    ret = False;
    # Normalize path
    if sel[0] == "~":
        sel2 = os.path.expanduser(sel)
    elif sel[0] != "/" :
        sel2 = os.environ['HOME'] + "/" + sel
    else: 
        sel2 = sel
    #print "is_mounted", sel2 
    mm = open("/proc/mounts").readlines()
    for aa in mm:
        sline = string.split(aa)
        if sel2 == sline[1]:
            ret = True
            break 
    return ret          

# Main applet code that creates the applet interface and updates the display

class HSapplet:

    def __init__(self, applet, iid):
         
        #syslog.syslog("Init Applet")       
        
        self.applet = applet
        self.apselect = None
        self.prefsdialog = None
        
        self.dict = {}
        self.ttext = "High Security Encrypting\n"\
                     "       File System"
        
        # Start from a known place
        os.chdir(os.environ['HOME'])
        
        #<menuitem name="Item 2" verb="Props" label="_Preferences" pixtype="stock" pixname="gtk-properties"/>
        
        self.propxml = """
        <popup name="button3">
        <menuitem name="Item 1" verb="Mounts" label="_Mounts" pixtype="stock" pixname="gtk-properties"/>
        <menuitem name="Item 3" verb="About" label="_About ..." pixtype="stock" pixname="gnome-stock-about"/>
        </popup>
        """
        
        #( "Props",  self.props ),
        self.verbs = [  
                        ( "Mounts", self.Mounts ),
                        ( "About",  self.about_info ) ]
            
        warnings.simplefilter("ignore", Warning)
        gnome.init("HSTray", "1.03")
        warnings.simplefilter("default", Warning)
        
        try:
            self.logo_pixbuf = gtk.gdk.pixbuf_new_from_file(\
                        os.path.basename(imgname))
        except:
            try:
                self.logo_pixbuf = gtk.gdk.pixbuf_new_from_file(imgname)
            except:
                try:
                    self.logo_pixbuf = gtk.gdk.pixbuf_new_from_file(imgname2)
                except:
                    pass
            
        self.ev_box = gtk.EventBox()
        #self.applet.set_size_request(-1, -1)
        
        self.ev_box.connect("event", self.button_press)
        self.applet.connect("change-background", self.panel_bg)
        
        self.main_icon = gtk.Image()
        main_pixbuf = None
        
        try:
            main_pixbuf = gtk.gdk.pixbuf_new_from_file(os.path.basename(imgname))
        except:
            try:
                #global imgname
                main_pixbuf = gtk.gdk.pixbuf_new_from_file(imgname)
            except:
                try:
                    main_pixbuf = gtk.gdk.pixbuf_new_from_file(imgname2)
                except:    
                    pass
                    #print "img", sys.exc_info()
       
        if main_pixbuf:    
            main_pixbuf2 = main_pixbuf.scale_simple(25, 25, gtk.gdk.INTERP_BILINEAR)
            self.main_icon.set_from_pixbuf(main_pixbuf2)
        else: 
            # This will let a broken image go through
            self.main_icon.set_from_file("")
             
        #self.label = gtk.Label("")
        self.main_hbox = gtk.HBox()
        
        self.main_hbox.pack_start(self.main_icon, False, False, 5)
        self.ev_box.add(self.main_hbox)
        
        self.main_hbox.show()
        
        applet.add(self.ev_box)
        applet.connect("destroy",self.cleanup,None)
        applet.show_all()
        
        # Set the tooltip
        self.main_hbox.set_has_tooltip(True)
        self.main_hbox.set_tooltip_text(self.ttext)
        
        # Mount automount entries. use ondemand for no prompt
        traydb2 = traySQL(traydbname)
        alldata = traydb2.getall()
        for aa in alldata:
            if aa[3] == "True":
                if not is_mounted(aa[2]):
                    ret = mountitem("-o", aa[1], aa[2], aa[4])
        
    def show_tooltip(self, tip):
        #print tip
        pass
        
    def props(self, win, arg):
        #print "props pressed"
        pass

    def Mounts(self, win, arg):
        #print "Mounts pressed"
        self.sel = MountSelector()
        self.sel.show()

    def cleanup(self,event,widget):
        del self.applet

    # Update the display on a regular interval (unused)
    def timeout_callback(self,event):
        #print "Timeout callback"
        return 1
        
    def button_press(self,widget,event):
        if event.type == gtk.gdk.BUTTON_PRESS:
            #print "pressed main button", event.button
            
            if event.button == 3:
                self.create_menu()

            if  event.button == 1:
                pass
            
    # Handle Gnome Panel background
    def panel_bg(self, applet, bg_type, color, pixmap):
        # Reset styles
        rc_style = gtk.RcStyle()
        self.applet.set_style(None)
        self.ev_box.set_style(None)
        self.applet.modify_style(rc_style)
        self.ev_box.modify_style(rc_style)
        
        if bg_type == gnomeapplet.PIXMAP_BACKGROUND:
            style = self.applet.get_style()
            style.bg_pixmap[gtk.STATE_NORMAL] = pixmap
            self.applet.set_style(style)
            self.ev_box.set_style(style)
        if bg_type == gnomeapplet.COLOR_BACKGROUND:
            self.applet.modify_bg(gtk.STATE_NORMAL, color)
            self.ev_box.modify_bg(gtk.STATE_NORMAL, color)
            
    def about_info(self,event,data=None):
        about = gnome.ui.About("HSENCFS", 
            "\n System tray for High Security Encrypting\n File System", 
                "Copyright (C) 2015 Peter Glen", 
                "Public Release One (V1.17)", ["peterglen99@gmail.com"])
        about.show()

    def properties(self,event,data):
        if self.prefsdialog != None:
            self.prefsdialog.window.present()
        else:
            self.prefsdialog = preferencedialog.PreferenceDialog(status, settings)
        return 1

    def create_menu(self):
        self.applet.setup_menu(self.propxml, self.verbs, None)

# ------------------------------------------------------------------------

class MountSelector:

    def __init__(self, title='HSENCFS Mounts', markup='Select Mount'):
        global traydb
        self.title = title
        self.markup = markup
        self.events = ""
        self.flags = gtk.DIALOG_MODAL | gtk.DIALOG_NO_SEPARATOR
        traydb = traySQL(traydbname)
        #traydb.verbose = True 
    
    def msg(self, dlgMarkup, Title=None):
        self.MsgDialog = gtk.MessageDialog(parent=None, 
                          type=gtk.MESSAGE_ERROR, buttons=gtk.BUTTONS_OK)
        if Title:                  
            self.MsgDialog.set_title(Title)                  
        self.MsgDialog.set_markup(dlgMarkup)
        
        self.MsgDialog.run()
        self.MsgDialog.destroy()
        del self.MsgDialog

    def show(self, items={}):
    
        self.items = items
        self.selection = None
        self.dlg = gtk.Dialog(title=self.title, parent=None, flags=self.flags)
        
        # Buttons
        self.cancel_button = self.dlg.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        self.ok_button = self.dlg.add_button(gtk.STOCK_OK, gtk.RESPONSE_OK)
        self.ok_button.set_sensitive(False)
        self.dlg.set_default_response(gtk.RESPONSE_CANCEL)
        
        # Instructions label
        self.instructions_label = gtk.Label()
        self.instructions_label.set_markup(self.markup)
        self.instructions_label.set_line_wrap(True)
        self.instructions_label.set_padding(15,15)
        
        # Description label
        self.description_label = gtk.Label()
        self.description_label.set_markup('')
        self.description_label.set_line_wrap(True)
        self.description_label.set_padding(15,15)
        self.description_label.set_alignment(xalign=0, yalign=0)    # Top left alignment
        
        # Create the icon for the dialog
        self.icon = gtk.Image()
        self.icon.set_from_stock(gtk.STOCK_SAVE, gtk.ICON_SIZE_DIALOG)
        
        self.icon.set_padding(15,15)
        self.dlg.vbox.pack_start(self.instructions_label, False, False, 0)
        self.dlg.vbox.pack_start(self.scrollwindow, True, True, 0)
        self.dlg.vbox.pack_start(self.description_label, False, False, 0)
        
        self.dlg.show_all()
        self.response = self.dlg.run()
        if self.response==gtk.RESPONSE_OK: # The user clicked the "connect" button
            return self.ok()
        else:
            return self.cancel()
        
    def ok(self):
        ss = self.treeview.get_selection().get_selected()        # Returns a (TreeModel, TreeIter) tuple
        if ss:
            self.selection = self.liststore.get_value(s[1], 0)
        self.dlg.destroy()
        del self.dlg
        
        return self.selection
        
    def cancel(self):
        self.dlg.destroy()
        del self.dlg
        return None

    def treeview_changed(self, widget, data=None):
        s = self.treeview.get_selection().get_selected()        # Returns a (TreeModel, TreeIter) tuple
        if s:
            self.selection = self.liststore.get_value(s[1], 0)
            try:
                self.description_label.set_markup(self.items[self.selection]['doc']())
            except:
                try:
                    self.description_label.set_markup(self.items[self.selection])
                except:
                    pass
        self.ok_button.set_sensitive(True)
        
    def treeview_clicked(self, widget, event, data):
        if event.type == gtk.gdk._2BUTTON_PRESS and event.button == 1:      # Double left-click
            self.dlg.response(gtk.RESPONSE_OK)

    def treeview_key_pressed(self, widget, event, data):
        if event.keyval == 65293: # Return key
            self.dlg.response(gtk.RESPONSE_OK)

    def load_settings(self):
        # Load the saved events
        try:
            self.events = pickle.loads(self.gconf_client.get_string(self.gconf_path+"/instances"))
        except (TypeError, KeyError, EOFError):
            self.events = []
        self.build_event_lookup()
        
    def delete_event(self, win, arg):
        pass
        
    def show(self):
        window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        window.set_border_width(10)
        #window.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)
        window.set_position(gtk.WIN_POS_CENTER)
        window.set_title("Mounts")
        window.set_size_request(-1, 400)
        window.connect("delete_event", self.delete_event)
        vbox = gtk.VBox(False, 15)
        vbox.set_spacing(10)
        window.add(vbox)
        
        self.window = window
        self.vbox = vbox

        self.window.connect("key-press-event", self.key_press_event)        
        
        # Create the liststore for the treeview
        self.listlookup = [ 'DataRoot', 'MountPoint', 'AutoMount', "MountOptions", 
                            'Comments' ]
        self.liststore = gtk.ListStore(str, str, str, str, str)

        # Create the treeview
        self.treeview = gtk.TreeView(self.liststore)
        self.treeview.connect("cursor-changed",self.treeview_changed,"")
        self.treeview.connect("button-press-event",self.treeview_clicked,"")
        self.treeview.connect("key-release-event",self.treeview_key_pressed,"")
        
        # Create the scroll frame for the list
        self.scrollwindow = gtk.ScrolledWindow()
        self.scrollwindow.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)

        # Add the treeview to the scroll frame
        self.scrollwindow.add_with_viewport(self.treeview)
        
        # Create the button box
        self.buttonbox = gtk.HButtonBox()
        self.buttonbox.set_layout(gtk.BUTTONBOX_START)
        self.buttonbox.set_spacing(10)
    
        # Create the buttons
        self.newbutton = gtk.Button(stock = gtk.STOCK_NEW)
        self.newbutton.connect("clicked", self.new_button_clicked, "")
        self.buttonbox.add(self.newbutton)

        #self.refreshbutton = gtk.Button(stock = gtk.STOCK_REFRESH)
        #self.refreshbutton.connect("clicked", self.refresh_button_clicked, "")
        #self.buttonbox.add(self.refreshbutton)

        self.editbutton = gtk.Button(stock = gtk.STOCK_EDIT)
        self.editbutton.connect("clicked", self.edit_button_clicked, "")
        self.buttonbox.add(self.editbutton)
        self.editbutton.set_sensitive(False)            # Disable the button

        self.deletebutton = gtk.Button(stock = gtk.STOCK_DELETE)
        self.deletebutton.connect("clicked", self.delete_button_clicked, "")
        self.buttonbox.add(self.deletebutton)
        self.deletebutton.set_sensitive(False)          # Disable the button

        self.mountbutton = gtk.Button("_Mount")
        self.mountbutton.connect("clicked", self.mount_button_clicked, "")
        self.buttonbox.add(self.mountbutton)
        self.mountbutton.set_sensitive(False)          # Disable the button

        self.umountbutton = gtk.Button("_UnMount")
        self.umountbutton.connect("clicked", self.umount_button_clicked, "")
        self.buttonbox.add(self.umountbutton)
        self.umountbutton.set_sensitive(False)          # Disable the button

        self.cancelbutton = gtk.Button(stock = gtk.STOCK_CLOSE)
        self.cancelbutton.connect("clicked", self.cancel_button_clicked, "")
        self.buttonbox.add(self.cancelbutton)
        #self.buttonbox.set_child_secondary(self.cancelbutton, True)
        
        idx = 0
        for aa in self.listlookup:
            # Add the columns to the treeview
            column = gtk.TreeViewColumn(aa,  gtk.CellRendererText(), text=idx)
            self.treeview.append_column(column)
            idx+=1
                
        # Load the treeview
        self.refresh_treeview()
        
        # Add the scroll frame to the main vbox
        self.vbox.pack_start(self.scrollwindow, True, True, 0)
        
        # Add the button box to the main vbox
        self.vbox.pack_end(self.buttonbox, False, False, 0)
        
        # Done, display window
        self.window.show_all()

    def mount_button_clicked(self, widget, data = None):
        global cursel, curmnt, curopt
        retcode = mountitem("-v", cursel, curmnt, curopt)
        if retcode[1] != "":
            self.msg("\nMount returned: %s\n" % retcode[1], 
                            "Error on Mount")    
        self.refresh_treeview()
        
    def umount_button_clicked(self, widget, data = None):
        args = ["fusermount", "-u", os.path.basename(curmnt)]
        #print args
        try:
            retcode = subprocess.Popen(args, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()
        except:
            retcode = None, "Cannot execute " + args[0]
            
        if retcode[1]:
            self.msg("\nUnMount returned: %s\n" % retcode[1], 
                            "Error on UnMount")    
        self.refresh_treeview()
        pass

    def refresh_treeview(self):
        self.liststore.clear()
        alldata = traydb.getall()
        for aa in alldata:
            self.liststore.append(aa[1:6])
        self.treeview_changed(self.treeview)
        
    def callback(self, res):
        aa = res.dataroot.get_text()
        missing =  "Missing Entry"
        if aa == "":
            self.msg("Must have Dataroot.", missing)    
            return False 
            
        aaa = os.path.abspath(os.path.expanduser(aa))    
        if not os.path.isdir(aaa):
            try:
                os.mkdir(aaa)   
            except:
                self.msg("\n%s\n" % sys.exc_info()[1], "Error on Directory creation")    
                return False 
            syslog.syslog("Created directory '%s'" % aaa)       
                
        if not os.path.isdir(aaa):
            self.msg("Directory does not exist: %s" % aaa, "Directory Check")    
            return False 
        
        bb = res.mountpoint.get_text()
        if bb == "":
            self.msg("Must have Mountpoint.", missing)    
            return False 
            
        bbb = os.path.abspath(os.path.expanduser(bb))    
        if not os.path.isdir(bbb):
            try:
                os.mkdir(bbb)   
            except:
                self.msg("\n%s\n" % sys.exc_info()[1], "Error on Directory creation")    
                return False 
            syslog.syslog("Created directory '%s'" % bbb)       
                
        if not os.path.isdir(bbb):
            self.msg("Directory does not exist: %s" % bbb, "Directory Check")    
            return False 
        
        cc = str(res.automount.get_active())
        dd =  res.mountopt.get_text()
        ee = res.comment.get_text()
        
        ret = traydb.put((aa, bb, cc, dd, ee, 0))
        if not ret:
            self.msg("SQL substystem responded: %s" % traydb.errstr,
                     "Data Error")    
        
        syslog.syslog("Created entry with '%s' '%s'" % (aaa, bbb))       
        self.refresh_treeview()             
        return ret 
        
    def new_button_clicked(self, widget, data=None):
        med = MountEd(self.window, self.callback)
    
    def refresh_button_clicked(self, widget, data=None):
        #self.connect_callback(MountSelector().show(self.preferred_networks))
        return 1
    
    def edit_button_clicked(self, widget, data=None):
        rowdata = []
        row = self.treeview.get_selection().get_selected()[1]   
        mnt = self.liststore.get_value(row, 1)
        if is_mounted(mnt):
            self.msg("\nCannot Edit '%s'. Entry is mounted \n" % mnt, 
                        "Cannot Edit")    
            return
        
        # Create tuple of current data:
        for aa in range(5):
            data = ""
            try:    data = self.liststore.get_value(row, aa)
            except: pass
            rowdata.append(data)
        MountEd(self.window, self.callback, rowdata)
        return 1
    
    def delete_button_clicked(self, widget, data=None):
        row = self.treeview.get_selection().get_selected()[1]   
        if row:
            mnt = self.liststore.get_value(row, 1)
            if is_mounted(mnt):
                self.msg("\nCannot delete '%s'. Entry is mounted \n" % mnt, 
                            "Cannot Delete")    
                return
            
            ret = traydb.rmone(self.liststore.get_value(row, 0))
            if not ret:
                self.msg("\nCannot delete data: %s\n" % traydb.errstr, "Error on Data Delete")    
            self.refresh_treeview()
        return 1
    
    def cancel_button_clicked(self, widget, data=None):
        self.window.destroy()
        return 1
        
    def treeview_changed(self, widget, data=None):
        global cursel, curmnt, curopt
        row = self.treeview.get_selection().get_selected()[1]       # Returns a (TreeModel, TreeIter) tuple
        
        # Reset buttons
        self.editbutton.set_sensitive(False )
        self.deletebutton.set_sensitive(False )
        self.umountbutton.set_sensitive(False )
        self.mountbutton.set_sensitive(False )
        if not row:
            return
            
        sel = self.liststore.get_value(row, 0)
        mnt = self.liststore.get_value(row, 1)
        opt = self.liststore.get_value(row, 3)
        cursel = sel; curmnt = mnt; curopt = opt
        
        self.editbutton.set_sensitive(True)
        self.deletebutton.set_sensitive(True)
        #mounted = is_mounted(os.path.basename(sel))
        mounted = is_mounted(mnt)
        self.umountbutton.set_sensitive(mounted)
        self.mountbutton.set_sensitive(not mounted)

        #print sel
        
    def treeview_clicked(self, widget, event, data):
        if event.type == gtk.gdk._2BUTTON_PRESS and event.button == 1:      # Double left-click
            self.edit_button_clicked(None,None)

    def treeview_key_pressed(self, widget, event, data):
        if event.keyval == gtk.keysyms.Return:
            self.edit_button_clicked(None,None)

    def key_press_event(self, win, event):
        if event.keyval == gtk.keysyms.Escape:
            self.window.destroy()
        
# Override the global (gtk) text view    
class TextView(gtk.TextView):

    def __init__(self, buffer = None):
        tv = gtk.TextView.__init__(self, buffer)
        return tv
        
    def get_text(self):
        buff = self.get_buffer()
        strx = buff.get_text(buff.get_start_iter(), buff.get_end_iter())
        return strx

    def set_text(self, val):
        buff = gtk.TextBuffer(); buff.set_text(val)
        self.set_buffer(buff)

# ------------------------------------------------------------------------
# Edit list of mounts:

class MountEd():
    
    def __init__(self, parent = None, cb = None, rowdata = None):
    
        self.cb = cb; self.rowdata = rowdata
        self.newdata = []
        
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_title("Mount Details")
        self.window.set_position(gtk.WIN_POS_CENTER)
        self.window.set_modal(True)
        self.window.set_transient_for(parent)
       
        www = gtk.gdk.screen_width(); hhh = gtk.gdk.screen_height();
        self.window.set_flags(gtk.CAN_FOCUS | gtk.SENSITIVE)
         
        self.window.set_events(  gtk.gdk.POINTER_MOTION_MASK |
                            gtk.gdk.POINTER_MOTION_HINT_MASK |
                            gtk.gdk.BUTTON_PRESS_MASK |
                            gtk.gdk.BUTTON_RELEASE_MASK |
                            gtk.gdk.KEY_PRESS_MASK |
                            gtk.gdk.KEY_RELEASE_MASK |
                            gtk.gdk.FOCUS_CHANGE_MASK )
         
        self.window.connect("key-press-event", self.key_press_event)        
        self.window.connect("button-press-event", self.area_button)        
        
        try:
            self.window.set_icon_from_file(imgname)
        except:
            try:
                self.window.set_icon_from_file(imgname2)
            except:
                pass
        
        xhbox = gtk.HBox(); self.hspacer(xhbox)
        vbox = gtk.VBox(); vbox.set_spacing(10)
        xhbox.pack_start(vbox)
        self.hspacer(xhbox)
        
        self.vspacer(vbox)
        table = gtk.Table();  table.set_row_spacings(10);  table.set_col_spacings(10)
       
        vbox.pack_start(table)
        table.xx = 0; table.yy = 0
        self.dataroot   = self.field(table,  "Data Root:   ",  gtk.Entry())
        self.mountpoint = self.field(table,  "Mount Point: ",  gtk.Entry())
        self.automount  = self.field(table,  "Auto Mount: ",      gtk.CheckButton())
        self.mountopt   = self.field(table,  "Mount Options: ",  gtk.Entry())
        self.comment    = self.field(table,  "Comment: ",      self.scrolltext())
        
        self.newdata.append(self.dataroot)
        self.newdata.append(self.mountpoint)
        self.newdata.append(self.automount)
        self.newdata.append(self.mountopt)
        self.newdata.append(self.comment)
        
        if self.rowdata:
            self.dataroot.set_text(self.rowdata[0])
            self.dataroot.set_tooltip_text(
                            os.path.abspath(os.path.expanduser(self.rowdata[0])))
            self.mountpoint.set_text(self.rowdata[1])
            self.automount.set_active(self.rowdata[2] == "True")
            self.mountpoint.set_tooltip_text(
                            os.path.abspath(os.path.expanduser(rowdata[1])))
            self.mountopt.set_text(self.rowdata[3])
            self.comment.set_text(self.rowdata[4])
       
        self.dataroot.set_width_chars(48)
        self.vspacer(vbox)
        
        hbox = gtk.HBox(); hbox.set_spacing(10)
   
        butt2 = gtk.Button(" _Cancel ")
        butt2.connect("clicked", self.click_can, self.window)
        hbox.pack_end(butt2, False)
        
        butt1 = gtk.Button("   _OK   ")
        butt1.connect("clicked", self.click_ok, self.window)
        hbox.pack_end(butt1, False)
        
        vbox.pack_start(hbox, False ) 
        self.vspacer(vbox)
        
        self.window.add(xhbox)
        self.window.show_all()
    
    # --------------------------------------------------------------------
    # Create scrollable text, embed scroll obj into text obj
    
    def scrolltext(self):
        
        text = TextView();
        text.sw = gtk.ScrolledWindow()
        text.sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        text.sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        text.set_border_width(8)
        text.set_accepts_tab(False)
        text.sw.add(text)
        
        return text
    
    # --------------------------------------------------------------------    
    # Create a field with prompt and all. If control has .sw, use it
    
    def field(self, table, prompt, control):       
        
        lab1 = gtk.Label(prompt)
        table.attach(lab1, table.xx, table.xx+1, table.yy, table.yy+1)
        try:
            if control.sw:
                table.attach(control.sw, table.xx+1, table.xx+2, table.yy, table.yy+1)
        except:        
            table.attach(control, table.xx+1, table.xx+2, table.yy, table.yy+1)
        table.yy += 1
        return control

    def spacer(self, hbox, xstr = "    "):
        lab = gtk.Label(xstr)
        hbox.pack_start(lab, False, False  )
       
    def hspacer(self, hbox, xstr = "    "):
        lab = gtk.Label(xstr)
        hbox.pack_start(lab, False, False  )
        
    def vspacer(self, vbox, padd = 10):
        hbox = gtk.HBox(); hbox.set_spacing(padd)
        vbox.pack_start(hbox, False, False  )
        
    def click_ok(self, butt, xx):
        # Callback to process. Return False to keep dialog up
        if self.cb(self):
            self.window.destroy()
        
    def click_can(self, butt, xx):
        self.window.destroy()
    
    def key_press_event(self, win, event):
        if event.keyval == gtk.keysyms.Escape:
            self.window.destroy()
    
    def  area_button(self, butt, arg):
        pass

# ------------------------------------------------------------------------
# Replaces g c o n f, so it is less platforrm dependent 

class traySQL():

    def __init__(self, file, verbose = False):
    
        self.verbose = verbose
        self.errstr = "None"
        self.c = None
        
        # List (tuple) of fields, types
        self.fieldx = ("dataroot", "text", "mountpoint", "text", 
                        "automount", "text", "options", "text", "ccomment", "text",
                        "ddate", "date")
                        
        self.table = "mounts"; 
        
        # Generate SQL fields 
        self.qm = ""; self.fields = "";  self.fieldnames = ""
        for aa in range(0, len(self.fieldx), 2):
            if aa > 0:
                self.fields += ", "; self.fieldnames += ", "; self.qm += ", "
            self.fields += self.fieldx[aa] + " " + self.fieldx[aa+1] 
            self.fieldnames += self.fieldx[aa]; self.qm += "?"
            
        #print "Fieldnames:", self.fieldnames
        #print "Fields:", self.fields
        
        homex = os.environ['HOME'] + "/.hstray/"
        if not os.path.isdir(homex):
            os.mkdir(homex)
            
        homex += file
        if self.verbose:
            print "Creating db", homex
        try:
            self.conn = sqlite3.connect(homex)
        except:
            if self.verbose:
                print "Cannot open/create db:", file, sys.exc_info() 
            return            
        try:
            self.c = self.conn.cursor()
            # Create table
            self.c.execute("create table if not exists " + 
                            self.table + " (pri INTEGER PRIMARY KEY, " + 
                                self.fields +  ")")
                                
            # Save (commit) the changes
            self.c.execute("PRAGMA synchronous=OFF")
            self.conn.commit()            
        except:
            self.errstr = sys.exc_info()[1]
            if self.verbose:
                print "Cannot create table", sys.exc_info() 
             
        finally:    
            # We close the cursor, we are done with it
            #c.close()    
            pass
    
    def __del__(self):
        #print "Deleting SQL instance"
        try:
            self.conn.commit()          
            self.c.close()
        except:
            self.errstr = sys.exc_info()[1]
            if self.verbose:
                print "Error on closing", sys.exc_info() 
            pass
        try:
            self.close()
        except:
            pass
        pass
        
    # --------------------------------------------------------------------        
    # Get All
    
    def   getall(self):
        rr = []
        try:      
            #c = self.conn.cursor()
            self.c.execute("select * from " + self.table)
            rr = self.c.fetchall()
        except:
            self.errstr = sys.exc_info()[1]
            if self.verbose:
                print "gatall: Cannot get sql data", sys.exc_info() 
        finally:
            #c.close   
            pass
        return rr
    
    # --------------------------------------------------------------------        
    # Return None if no data
    
    def   get(self, kkk):
        try:      
            #c = self.conn.cursor()            
            self.c.execute("select * from " + self.table + 
                    " where " + self.fieldx[0] + " = ?", (kkk,))
            rr = self.c.fetchone()
        except:
            if self.verbose:
                print "get: Cannot get sql data", sys.exc_info() 
            rr = None
        finally:
            #c.close   
            pass
        if rr:           
            # Do not return ID 
            return rr[1:]
        else:
            return None

    # --------------------------------------------------------------------
    # Delete one
    
    def   rmone(self, kkk):
        #print "rmone '" + kkk + "'"
        rr = True 
        try:      
            #print "delete from " + self.table  +
            #        " where " + self.fieldx[0] + " == ?", (kkk,)
                    
            self.c.execute("delete from " + self.table + \
                 " where " + self.fieldx[0] + " == ?", (kkk,))
            rr = self.c.fetchone()
            rr = True 
            self.conn.commit()          
        except:
            self.errstr = sys.exc_info()[1]
            if self.verbose:
                print "rmone: Cannot delete sql data", sys.exc_info() 
            rr = None
        finally:
            #c.close   
            pass
        return rr 

    # --------------------------------------------------------------------
    # Put mount info into table
    
    def   put(self, data):
    
        #print data[0], "data", data
        #got_clock = time.clock()         
        
        ret = True; idx = ""  
        try:      
            #c = self.conn.cursor()
            self.c.execute("select * from  " + self.table + " where " + 
                self.fieldx[0] + " == ?", (data[0],))            
                
            rr = self.c.fetchall()
            if rr == []:
                print "insering", data
                self.c.execute("insert into " + self.table + "( " + 
                    self.fieldnames + ") " + "values (" + self.qm + ")", (data))
            else:
                #print "updating", data
                xstr = "update " + self.table + " set "
                for aa in range(0, len(self.fieldx), 2):
                      if aa > 0: xstr += ", " 
                      xstr += self.fieldx[aa] + " = ? "
                      
                xstr += "where " +  self.fieldx[0] + " = ? " 
                data2 = list(data); data2.append(data[0])
                #print xstr, data2
                self.c.execute(xstr, data2)                                     
            self.conn.commit()          
        except:
            if self.verbose:
                print "Cannot put SQL data", sys.exc_info()             
            self.errstr = sys.exc_info()[1]
            ret = False  
        finally:
            #c.close     
            pass
            
        #self.take += time.clock() - got_clock        
        return ret
    
# =-----------------------------------------------------------------------

if len(sys.argv) != 2 or sys.argv[1].find("window") == -1:

    print 
    print "WARNING: hstray is not intended to be run directly from the command line."
    print "Use 'hstray.py run-in-window' to run in a window."
    print 


def HS_applet_factory(applet, iid):
    try:
        HSapplet(applet, iid)
    except:
        print  sys.exc_info()
        traceback.print_tb(sys.exc_info()[2])
      
    return True

def key_press_event(win, event):
    if event.keyval == gtk.keysyms.Escape:
        win.destroy()


# Starting here ... this is mainly for development

if len(sys.argv) == 2 and sys.argv[1].find("window") != -1:

    syslog.openlog("HSENCFS Tray")
    syslog.syslog("Starting in window")
    
    main_window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    main_window.set_title("HSENCFC Applet")
    main_window.connect("destroy", gtk.main_quit) 
    main_window.connect("key-press-event", key_press_event) 
    app = gnomeapplet.Applet()
    HS_applet_factory(app, None)
    app.reparent(main_window)
    main_window.show_all()
    gtk.main()
    
    syslog.syslog("Ended window")
    sys.exit()
        
# ------------------------------------------------------------------------        
        
if __name__ == '__main__':

    syslog.openlog("HSENCFS Tray")
    syslog.syslog("Starting embedded")
    
    try:
        gnomeapplet.bonobo_factory("OAFIID:GNOME_HSENCApplet_Factory",
                gnomeapplet.Applet.__gtype__,"", "0", HS_applet_factory)
    except:
        print  sys.exc_info()
        syslog.syslog("Ended with exception. %s", sys.exc_info()[1])
        sys.exit(1)
        
    syslog.syslog("Ended Normally.")
    sys.exit(0)






