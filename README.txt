
Network Topology:

The network topology we used consists of 4 hosts, 1 OVS switch and a con-
troller. The topology is created using GENI by reserving the machines in the
GENI rack. Once the topology, all the machines were brought into the same
subnet. We login to the machines using SSH, the public and private keys
are generated for each user. The 4 hosts are connected to the OVS switch
through 4 ethernet interfaces. This topology is scalable and can be extended
to multiple hosts and OVS switches.

Attack
The attack is launched using hping3[22] tool. This attack generates a surge
of trac which depletes the network resources. All the trac is mapped to
a single port listening on an interface eth1. Whenever an attack is launched
Snort listens the trac on common interface eth1 providing the ability to
detect the attacks from multiple hosts. We detect the trac using Snort
rules by setting up a threshold value raising an alert. We changed the Snort
conguration le to log the information in csv format.

Detection Methodology
We run the Snort in logger mode, it logs the alerts to a csv le. When the
pings are below the threshold Snort does not log anything but when thresh-
old is reached it logs the information. The logged information consists of
IP addresses from source and destination hosts and its respective MAC ad-
dresses.

Socket Programming
An algorithm based on socket programming provides the communication
mechanism between OVS switch and the controller. All the OVS switches in
the topology hosts a client socket program called csock which keeps listening
for alerts from Snort. If csock receives any alert from the Snort, csock imme-
diately scans the log directory of the Snort and gets the information from the
logged le. Before extracting the attack node and victim node information
from the le, csock should make sure le is unlocked. A locked access csv le
means the le is currently in use by some other program. In this scenario
it is Snort who is writing the attack information. Hence csock should give
a repeated trial to get access to the csv le. Once csock gained the access
to the le it should immediately rename it to give way for Snort to create a
new log csv.
A single alert message in csv le comprises of the node IP address and MAC
address of both attacker and victim nodes. It also contains the alert infor-
mation and the protocol used, but the csock only parses and extracts the
MAC addresses of both the nodes and opens the socket to the controller IP
with pre-dened port number. If other OVS switch is already listening to
controller, the current connection will fail. It is necessary for csock to recon-
nect the socket after few milliseconds of delay. Once the socket is successfully
connected to the controller, csock will write both attackers and victims MAC
addresses to the buer that will be read at controller end.
The controller hosts a server socket program called ssock. Ssock keeps lis-
tening to the pre-dened port if any client wants to communicate it will
establish a connection and receives the message. The controller will then get
the message from the ssock and adds it in the rewall table.
The rewall program uses the open source pox API[16], match.dl src match-
ing the source MAC, msg.match.dl dst matching the destination MAC and
of.ofp action output takes the action to drop the ows. The rewall program
parses the MAC addresses and install the rules to drop the packets using
above stated pox APIs. When ssock receives the message from the csock it
updates the rewall table. Once the rewall table is updated the controller
has to be restarted to establish the new ow for dropping the packets from
the attacker.