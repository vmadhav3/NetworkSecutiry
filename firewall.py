from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os


import csv 


log = core.getLogger()
addressesfile = "/tmp/pox/mac-addresses.csv" 

class blocking (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling blocking Module")

        self.blocklist = []; # addresses list

    def readFromCVS(self):
	    # remove duplication
	    # add reverse entry 
	    print addressesfile
	    csvFile = open(addressesfile, 'rb');
	    inStream = csv.reader(csvFile, delimiter=',')
            for row in inStream:
		#print row
                self.blocklist.append(row)

            self.blocklist.pop(0)

            for item in self.blocklist:
                item.pop(0)

    def _handle_ConnectionUp (self, event):
         self.readFromCVS()
       	#print self.blocklist 
	
        for item in self.blocklist:
            msg = of.ofp_flow_mod()
	    #print item[0], item[1]
            msg.match.dl_src = EthAddr(item[0])
            msg.match.dl_dst = EthAddr(item[1])
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(msg)
            log.debug("blocking rules installed on %s", dpidToStr(event.dpid))
            log.debug("Link bteween %s to %s is added", item[0], item[1])

	
def launch ():
    
    core.registerNew(blocking)