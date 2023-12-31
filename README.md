# What does the Assimilation Project do?
The Assimilation project creates a continually updated and very detailed map (CMDB)
of system and network configuration in a way that scales better than any other known system.
This information is sufficiently detailed to determine if systems are misconfigured, contain
hacked software, or are configured in violation of best practices (security or other).
To the degree possible, this is performed with near-zero manual configuration,
as manual configuration is eventually incorrect (often sooner than later).

# What are the downsides of the Assimilation Project?
The Assimilation project requires active agents on most programmable network endpoints (i.e., servers).
Although this requirement can be a show stopper for some organizations, without agents,
scaling is typically problematic, often highly so.
With the Assimilation architecture, even massive scaling can be achieved with minimal resources.

# What are the architectural components of the Assimilation software?
Each Assimilation installation consists of a central Collective Management Authority (CMA)
and a large number of active agents called nanoprobes.
Nanoprobes act strictly under the direction of the CMA.
This README primarily provides details about nanoprobes, and discussions of how the
CMA works, and how it uses nanoprobes are outside the scope of this README.

# What Is a nanoprobe?
A nanoprobe is an active agent that is widely distributed across the network
to monitor liveness of systems in the network, perform discovery of the configuration
of the system it is attached to, and monitorin its services.
In an ideal world, every programmable endpoint would have a nanoprobe running on it.
Liveness of systems is determined by the exchange of heartbeat packets.
It is intended that nanoprobes be as simple as possible, and do little or nothing on their own.

# How do nanoprobes work?
Nanoprobes, except during initialization, do only what they've been told to do by the CMA.
Many of the actions required for discovery operations require high levels of privileges. 
Nanoprobes must ensure that they are operating at the lowest level of privilege necessary to perform the task at hand.
Discovery data is potentially highly sensitive, and the level of privilege necessary means that security
must be taken seriously from the ground up.
The way to think of discovery data for an entire network, is that discovery data is not the buried treasure,
but a map of where the buried treasure is.
Such a map would be extremely valuable to an adversary.

## During Initialization
During initialization, it sends out a single (reliable) packet to announce that it is now alive.
Depending on local configuration this could be to a multicast address, or a unicast address.
*It also automatically does some basic and well-known discovery of the local OS configuration, I think???*

The normal startup sequence for a nanoprobe is as follows:
 1. Nanprobe starts up (main program is activated)
 2. Nanprobe sends and "*I've just started*" message to the CMA.
    This might be to the reserved multicast address for the project,
    or to a unicast address (if one was configured).
    This message contains local OS version information, and the public key of this
    nanoprobe.
 3. The CMA replies to the nanoprobe (including its "true" unicast IP address),
    tells the nanoprobe the addresses of its heartbeat partners,
    what discovery actions it is to perform, and how often..
 4. The nanoprobe performs these actions, and sends the results to the CMA.
    Results of discovery actions are not retained by nanoprobes across restarts.

## After Initialization
Once a nanoprobe is initialized, it does these things:

 * Listen for and acts on messages it receives from the CMA.
   These messages tell the nanoprobe where the CMA is located, which discovery actions to perform, 
   what systems to send and expect heartbeats from, and what other things to listen for (as noted below).
 * Listen for heartbeat packets from assigned neighbors, and report lack of heartbeats to the CMA
 * Send heartbeat packets on a timed basis to assigned neighbors
 * Listen to ARP broadcasts (to discover IP/MAC pairings on network interfaces) and notifies the CMA of changes
 * Listen for LLDP packets from switches it is connected to (to discover network topology) and notifies the CMA of changes
 * Perform discovery actions on a repetitive timed basis, as requrested by the CMA.
 * Perform monitoring actions on a repetitive timed basis, as requrested by the CMA.

## Discovery Actions
Discovery actions produce JSON describing the things that have been discovered.
If a discovery action produces the same JSON as it did previously, the discovery data is discarded.
On \*nix systems including Macs, discovery actions are typically performed by shell scripts.
Because of differences between \*nix systems, the scripts may differ from platform to platform.
On Windows systems, discovery actions are typically performed by PowerShell scripts.
It is intended that regardless of OS environment, that certain types common of discovery actions (e.g., network topology)
produce very similar JSON.

## Capabilities required for nanoprobes
 * Initiate a reliable connection to the CMA
 * Reliably communicate with the CMA, receiving orders, and sending results
 * Send heartbeats to peer nanoprobes
 * Listen for heartbeats from peers, and report to the CMA on "missing" peers
 * Perform discovery actions as requested, including initial results, and timed repetitions of discovery actions
 * Listen to ARP broadcasts
 * Listen to LLDP packets

## Virtualized environments
 * In an ideal world, nanoprobes operate at the lowest level available (bare hardware, or virtual machines)
 * Putting nanoprobes into all containers is to be avoided. A privileged daemonset is a much better idea.

# About communication
 * All communication between nanoprobes and the CMA is reliable, encrypted and digitally signed with public key encryption.
 * Heartbeats between nanoprobes are unsigned, unencrypted, and unreliable UDP packets.í
 * Nanoprobes are *given* the public key of the CMA.
 * The CMA learns of the public keys of nanoprobes when they initialize.
   TOFU (trust on first use) is used to validate nanoprobe keys.
 * It is required that a nanoprobe be tolerant of the CMA being temporarily unavailable.
 * The CMA is permitted to assume that anything that a nanoprobe needs to tell it will eventually arrive, unless the nanoprobe restarts (see below).
 * When a nanoprobe restarts, loss of all pending communications is expected.
 * The current protocol supports sending binary data, which would support proxies (see below) encapsulating and re-signing encrypted data from their clients.
   It seems likely that this aspect of the current protocol should be retained - and keeping compatability with the existing CMA code
   has value.

# Food for Thought (mostly architectural level issues, mostly not nanoprobe issues)
Not all of these need to be solved soon, but need to be given good thought over time.
 * Connect the new code to [OpenTelemetry](https://opentelemetry.io/), in such a way as it can be turned on or off.
 * How to uniquely identify network addresses and system names in the presence of VPNs, VLANs, virtual systems and containers?
 * How to deal with isolated network segments in this complex environment
   * Separate CMAs?
   * Proxy layers? (if so, how to discover or configure them)
   * SSH or equivalent?
   * VPNs?
   * Something else?
 * How to deal with multi-homed environments (different LANs/VLANs on different NICs)
 * Rekey operations on nanoprobes or the CMA
 * What about switches and routers that are able to run nanoprobes?
   * What is different when you have dozens or hundreds of interfaces?
   * How to account for this complexity in the CMA?
 * Discovery of Kubernetes environments
 * Discovery in an AWS or Azure environment
 * What about more aggressive discovery of unknown network entities? Nmap? SNMP?
 * What about more automatic installation of nanoprobes?
 * Management of (CMA) secrets (not automatically configured :-))
   * HashiCorp Vault?
   * AWS secrets?
   * Azure secrets?
   * Some combination of these?
   * Other?

# Why rewrite the nanoprobe - and why Rust?
The previous "C" code version of the nanoprobe worked well, and it was a reasonable design - so why rewrite it at all?
The answer is that it never ran on Windows, and that building it to be portable and run on all Linux systems from a
single binary was a horribly complicated kludge.
Building separate version for each and every version of Linux was even worse.
So going to a language like Rust or Go which can cross-compile to many environments would eliminate this complexity
and build-system-fragility.
In addition, few people want to work on C code, which isn't a good thing when it comes to looking for developers
for open source projects.

The nanoprobe is designed to be a very low-profile and consume few resources, and run indefinitely without needing a restart.
Here are the characteristics which I believe are necessary for such systems:
 * Compiled (small size, fast execution)
 * Clear memory management
 * Zero memory leaks
 * No garbage collection

Of the modern languages, only Rust satisfies all these criteria.
Some may wonder why garbage collection is on the prohibited list.
The answer to that is that programs in garbage collected languages grow and grow in size until they are garbage collected.
While they are growing, they kick the operational software out of memory for their own growth,
impairing the system they are monitoring.
Some may answer, just tell it how much memory they need, then they'll not kick everything out of memory.
Such tuning is fragile, and will eventually be incorrect.

Other points in Rust's favor:
 * When you talk about heartbeats,
   the process of garbage collection tends to impair the real-time behavior for such features,
   and getting rid of garbage collection makes the detection of nanoprobe (system) death more reliable.
 * Rust's compile-time checking of storage use and concurrency are strong points in its favor
   when thinking about high-trust systems such as the Assimilation project.

# Approaches to writing this code in Rust
I'm just now learning Rust, but the old nanoprobe code in "C" is quite solid, and can serve as a good model,
but none of it is yet written in Rust.
Here are the different dimensions that I see I could as semi-independent development chunks:
 * A subsystem for secure invocation of discovery agents with specified capabilities
   (the C-based code doesn't include capability annotations)
 * A subsystem for secure invocation of monitoring agents with specified capabilities
   (the C-based code doesn't include capability annotations)
 * The communication (protocol) code. (Reliable, encrypted, signed over UDP)
 * Heartbeat sending and receiving (over UDP)
 * Listening to ARP broadcasts
 * Listening to LLDP broadcasts
