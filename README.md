Explanation of WRedLogger.py:  
This is the script that drives the current NETDBG backend. In order to use it, adjust dirName and the port number (420 near the end of script) to your needs.  
After that, change the IP address on the info.sin_addr.s_addr line of kern_netdbg.cpp to your external IP, and rebuild the Kext.  
NyanCatTW1 \*might\* be able help you set it up, but there are no guarantees.  
