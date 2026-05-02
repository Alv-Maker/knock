## knock: A port-knocking implementation

Base code: Copyright (c) 2004, Judd Vinet <jvinet@zeroflux.org>
Modifications' code: Copyright (c) 2025, Alberto Nóvoa González <angonzalez22@esei.uvigo.es>

# Dependences:
- libpcap
- autoconf tools (for building from source)

# Installation process:
1. Clone the repository.
2. Navigate to the cloned directory and run the following commands:
`
$ autoreconf -fi
$ ./configure --prefix=/usr/local
$ make
$ sudo make install (only if you want to install it system-wide, otherwise you can run the binary from the build directory)
`
3. Edit the configuration file (default: /etc/knockd.conf) to set up your desired port knocking sequences and actions. Don't specify protocols or flags, this things are not supported in this implementation, but yet can be written in the configuration file, but they will be ignored.

# Usage:
- To start the knockd daemon: `sudo knockd -c /path/to/knockd.conf` (parameter c is not required if you are using the default configuration file path)
- Copy the sequence book to the client machine (default: credential_0.txt) using a secure method (e.g., scp, sftp). This process is done by the administrator because we understand that the processes can vary a lot.
- To send a knock sequence: `knock -f /path/to/sequence_file.txt` (parameter f is not required if you are using the default sequence file path)

# Dynamic port knocking:
This implementation supports dynamic port knocking, this means that the knocking sequence is not static and change every time a knock sequence is sent. Initially, and hasta the version 0.92 this process was done using MQTT server, with topics changing every time too. But in the latests versions the dynamic port knocking is done using a sequence file, reducing the exchange of information between the client and the server, and also reducing the attack surface of the implementation.

# Message sending:
This implementation also supports sending a custom message to the client in the sequence file, using variable slices to separate the message between the knocking sequence. This message go in clear, so it is not recommended to use this feature if you are sending sensitive information, but it can be useful for future uses.

# Thanks:
- Judd Vinet for the original implementation of knockd and the contributors that have contributed to the original project.
- To you, for reading this README and using this implementation of knockd, I hope it can be useful for you and your projects.

I am trying to improve this implementation yet, understand that this is a work in progress and that there are still some features that I want to add.