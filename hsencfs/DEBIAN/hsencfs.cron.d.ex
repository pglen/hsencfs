#
# Regular cron jobs for the hsencfs package
#
0 4	* * *	root	[ -x /usr/bin/hsencfs_maintenance ] && /usr/bin/hsencfs_maintenance
