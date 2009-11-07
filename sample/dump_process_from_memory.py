#/usr/bin/env python

import landfill 
import subprocess

if __name__ == "__main__":
    process_name = "gcalctool"

    # find pid from process name
    pid = subprocess.Popen("ps -C %s -o pid" % process_name, \
                            shell=True,                      \
                            stdout=subprocess.PIPE)
    stdout = pid.communicate()[0]
    try:
        pid = int(stdout.split('\n')[1])
    except ValueError:
        print "Process could not be found"
        exit()

    l = landfill.landfill(pid)
    l.rebuild_elf()
