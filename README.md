This folder contains sources for TCPR with support for SSL.

TCPR, also available from <http://github.com/rahpaere/tcpr/>, is middleware
that enables application-driven TCP migration and recovery.  The
setup-network script uses features available in recent Linux kernels
to create a virtual network, and setup-tcpr installs firewall rules to
protect all TCP connections to one of the nodes; they can be used as
examples for using TCPR with dc.

Install the OpenSSL library. This library has a custom memory
allocation function in the file crypto/mem.c. This function allocates
a big chunk of memory for the first time and then for the subequent
requests, it allocates memory from the same block. This is helpful
in taking the backup of SSL state which is required in failsafe
recovery of the application.  Change the /crypto/mem.c file to use
the custom malloc function.  Please do not forget to install libssl
package for SSL library headers.

We provide an example application, dc for "data collector", and this is
used in the context of the GridControl project (jointly with WSU).
Usage:

	dc [args] src-ip src-port stream-id dst-ip dst-port
		Optional arguments:
			-l log-file:  prefix of log file name [default = no logging]
			-s log-size:  maximum size of a log file [default = unlimited]
			-n log-count: maximum #log files [default = unlimited]

The data collector connects to both src-ip:src-port and dst-ip:dst-port
with SSL. It sends the stream-id to the source, and then copies all
data it receives from the source to the destination.  It protects its
connection to the source with TCPR.

When a data collector starts up, it requests the latest state from
TCPR, and, if a non-failed connection is present, the data collector
connects directly to the master and waits for it to die.  The current
implementation uses TCPR and detects failure in such a way as to be
completely safe in the face of a data collector process failing, but
for simplicity it does not check for network stack or TCPR failure.

To demonstrate the data collector,  we have included two other apps:

	pmuplayer [-p port (default = 3350)]
	pmudumper [-p port (default = 3360)]

The pmuplayer can be used as a source, and the pmudumper as a destination.
The pmuplayer plays the contents of the included file out.0230.dat,
which is a dump of 600 seconds of PMU data from a particular device.
When replaying the PMU data, pmuplayer updates the timestamps.
The pmudumper reads PMU data and prints it on standard output in a
human-readable format:

	time:msec - voltage-amplitude voltage-angle current-amplitude current-angle

The files c37.c and c37.h contain various useful C routines for parsing
data formatted according to C37.118 (IEEE Standard for Synchorphasors
for Power Systems).  Given a 42-byte buffer containing a data frame,

	c37_packet *get_c37_packet(char *data)

returns a c37_packet data structure.

	void write_c37_packet(FILE *output, c37_packet *pkt)

writes a packet in C37.118 format to the given FILE, while

	void write_c37_packet_readable(FILE *output, c37_packet *pkt)

prints the human-readable version defined above.

To conduct a demo like the one at
<https://www.youtube.com/watch?v=BPIvZBSJ5vk>, first set up a virtual
network with four nodes and configure TCPR:

	$ ./setup-network 4
	$ ./setup-tcpr

Then, open four new terminals.  In one, start the data source:

	$ ./node 0 ./pmuplayer

In another, start the data sink:

	$ ./node 3 ./pmudumper

In the middle two, start shells on the two replicas:

	$ ./node 1

	$ ./node 2

Then, in either replica shell, run the data collector:

	$ ./dc 10.0.0.1 3350 1 10.0.3.1 3360

At any time, in any order, you can start another dc (the same way),
and kill a running one.  When you're done, kill the pmuplayer.
