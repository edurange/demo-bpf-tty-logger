# TTY Logging with BPF
See https://github.com/edurange/demo-bpf-tty-logger.
Demonstrates how to capture TTY activity using BPF kernel probes.

# Instructions

To run it one needs to have superuser privileges (for kernel access). The probes intercept all TTY activity on the host system - both inside and outside of containers. If the script is printing to a TTY device the prints themselves will also be observed, creating a feedback loop that will quickly meet the limits of the kernel buffers. As such the output should be redirected to a file. I recommend redirecting both STDOUT and STDERR as follows:

```sudo python3 parrotty.py &> log```

# Explanation

parrotty.py is compact but there's a lot going on. Unlike ttylog and analyze.py, which it would replace, parrotty.py does not rely on changing or proxying the TTY device itself. Rather, it utilizes Berkeley Packet Filters, a kernel-level interface for hooking code into system calls; see also https://www.kernel.org/doc/html/latest/bpf/index.html for a specific implementation of the BPF interface. Instead of intercepting at the point of the TTY connection, we tamper with and tap the kernel calls that provide TTY services system-wide.

## Berkeley Packet Filter

BPF links compiled object code into the kernel. Newer extensions to BPF support using pre-compiled code payloads, but typically the code is loaded at runtime from C, with a tool such as cling. It looks odd by Python standards, but the common practice is to embed a one-file C program as a string in the Python file, then send it to be compiled and linked in through the BPF API.

The main area of interest are the functions injected into the kernel, called probes - kprobe__tty_write() and kprobe__n_tty_receive_buf_common(). The prefix "kprobe__" tells BPF to use these functions as probes automatically (but it's possible to use arbitrary functions, with an additional call to identify them.)

tty_write() and tty_receive_buf_common() are used to copy data in and out of kernel memory, as user-land processes talk to the physical device drivers represented in software by the TTY resource. In its basic usage, BPF calls the probe with the same parameters that the system call received. We use this to read the data buffers as TTY devices transmit and receive.

To safely permit alterations to the kernel, BPF enforces static compile-time checks above and beyond normal C language requirements. The kernel probe code may appear pedantic as a result, but the aggressive null pointer guards are necessary for approval by the BPF checker.

## Timing

BPF lacks a wall clock time source. In other words, all of the time values available in the kernel under BPF are based on the system's uptime clock, not a time source synced to time of day. The uptime clocks have some unintuitive behavior compared to typical timepieces. When the host system is halted or put to sleep, the clocks stop. From the perspective of software running on the host system, the system clocks move forward at a smooth rate, but the wall clock time jumps forward unpredictably whenever the system wakes from sleep.

To account for this, first the raw time values must be captured as close to the actual TTY event as possible - preferably, as the first instruction in the probe. We note the system time as part of the record of the TTY event, which is then exfiltrated from the kernel using a shared memory buffer provided by BPF.

In user space a handler function in the outer Python script reads events from the BPF buffer. There we have full access to wall clock time. Measuring the difference between system uptime and wall clock time is as simple as capturing both values, but it may occasionally jump as a result of changes to the offset value used to calibrate it - such as when the system receives a time update via network time protocol, which can occur quite frequently on modern operating systems.

To watch for drift in the clock offset, we take the difference between the current system-wide wall clock time and the time extrapolated by adding our offset estimate to the most recent timestamp. If the drift between the two time sources exceeds some small threshhold, we calculate a new offset value. We also recalibrate the offset value on a regular interval, even if it doesn't exceed the drift limit. In our implementation we chose a drift threshold of one thousandth of a second, and a refresh timeout of one minute.

The timing values are captured in a closure to avoid reliance on mutable global variables. calibratetimefactory() encloses the timing values with the method that updates them. API consumers need only call the resulting calibratetime() function to receive updated timing information, while being discouraged from tampering with the internal representation and underlying algorithm.

## Event Attributes

As mentioned, because this code runs in the kernel whenever the relevant system calls are invoked, it sees all TTY activity - from all processes and all users. Unlike ttylog, we are not attached to one particular TTY device. To distinguish between calls made by different services on behalf of different endpoints, we must record additional data about each system call event.

In the order that they appear in the code, not necessarily by relevance:

- `rawtime`: The raw value of the system uptime clock when the event was captured. Represented as nanoseconds of CPU runtime since boot up. A "monotonic clock" in hardware design terminology.

- `cgid`: The "**C**ontrol **G**roup **ID**" (sometimes shortened "Cgroup") is a Linux mechanism for grouping processes and other resources heirarchically. It can be used in some circumstances to identify processes as belonging to containers. Cgroups are a Linux kernel feature that do not have a direct analog on other POSIX systems, but so is BPF, so while I'd like to stick to POSIX compatibility where possible that's just not relevant in this context.

- `inode`: The "**i**ndex **node**" refers to the file-like object associated with the TTY device or psuedoterminal that is transmitting/receiving. This is a primary source of identifying information for our purposes, but there are some circumstances where it isn't available, and there are also cases where inode values will differ but we want to associate the data together anyways, such as when we see the same student log in on more than one terminal.

- `pidtgid`: This encodes two values which come from BPF packed into a single variable - PID, the "**p**rocess **ID**" of the main thread, and TGID, the "**t**hread **g**roup **ID**", which may contain a different ID for the current thread if the process has more than just a main thread.

- `nsid`: This contains the "**n**ame**s**pace **ID**" of the calling process, which can help to identify containerized processes in some circumstances where CGID and PID/TGID leave ambiguity.

- `comm`: This is the "**comm**and name", a fixed-length 15-character identifier of the calling process. It is often not unique, and sometimes truncated and/or mangled, but may provide additional context in some situations and enhances the human readability of events.

- `buf`: This is the "**buf**fer". This is the C byte array that the kernel received from the caller, representing the data being communicated. It may be as long as a kernel page, which is 4kB on contemporary systems, and may or may not be null-terminated. The buffer contains raw bytes that have not been interpreted according to any text encoding, and in some cases the buffer will not be decodable by itself - multi-byte characters (like from Unicode) are not guaranteed to be complete and may be split between two buffer flushes. What this means is that text needs to be assembled and decoded at a higher level than we are working at while just capturing the data.

- `len`: The number of bytes in the buffer. Not the same as the characters represented in the buffer. Definitely not the same as the number of characters that will show up on the terminal.

- `event`: This indicates the directionality of the event, from the perspective of the host system. INPUT events indicate data received from the student's terminal or client process. OUTPUT events indicate data being transmitted to the student or client.

In the Python output, there are some derived values which are not recorded in the BPF probes, but calculated in the outer Python handler:

- `pid` is derived from the upper 4 bytes of the combined `pidtgid` value, by shifting out the lower bytes.

- `tgid` is derived by masking off the lower 4 bytes of the combined `pidtgid` value.

- `time` is derived by adding the aforementioned clock offset calculation to the `rawtime` value.

# Example Output

The following output is the result of the command `echo Hello, World!`.

Notice most physical events are associated with four system calls, two each to both n_tty_receive_buf_common() and tty_write(). Input events are followed by output events because the terminal is configured to echo buffered characters so the user can see them - sshd is sending bytes back as the user enters them. But n_tty_receive_buf_common() is called twice because that's how the kernel uses it. The TTY system call is used once to copy the buffered data from the TTY device driver to the kernel, and then again from the kernel out to the userland process that made the system call.

Another point of interest is in the final results of evaluating the command, where you can observe bash emitting control characters and replacing POSIX-style newlines ("\n") with xterm-style ("\r\n").

```
<INPUT pid=2579 tid=2579 time=1751051966371111181 rawtime=203335230775 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'e'
<OUTPUT pid=67 tid=67 time=1751051966372044241 rawtime=203336163835 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'e'
<INPUT pid=2580 tid=2580 time=1751051966372190646 rawtime=203336310240 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'e'
<OUTPUT pid=67 tid=67 time=1751051966372639326 rawtime=203336759469 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'e'
<INPUT pid=2579 tid=2579 time=1751051968089522310 rawtime=205053641539 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'c'
<OUTPUT pid=67 tid=67 time=1751051968089690488 rawtime=205053809717 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'c'
<INPUT pid=2580 tid=2580 time=1751051968089802828 rawtime=205053922397 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'c'
<OUTPUT pid=67 tid=67 time=1751051968089833388 rawtime=205053952388 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'c'
<INPUT pid=2579 tid=2579 time=1751051968250835993 rawtime=205214954887 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'h'
<OUTPUT pid=67 tid=67 time=1751051968250966010 rawtime=205215084904 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'h'
<INPUT pid=2580 tid=2580 time=1751051968251302359 rawtime=205215421253 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'h'
<OUTPUT pid=67 tid=67 time=1751051968251330720 rawtime=205215449614 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'h'
<INPUT pid=2579 tid=2579 time=1751051969762481565 rawtime=206726601086 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051969762631118 rawtime=206726750639 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2580 tid=2580 time=1751051969762777304 rawtime=206726896825 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051969762801534 rawtime=206726921161 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2579 tid=2579 time=1751051970952290018 rawtime=207916408780 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b' '
<OUTPUT pid=67 tid=67 time=1751051970952415054 rawtime=207916533816 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b' '
<INPUT pid=2580 tid=2580 time=1751051970952582323 rawtime=207916701085 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b' '
<OUTPUT pid=67 tid=67 time=1751051970952645255 rawtime=207916764825 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b' '
<INPUT pid=2579 tid=2579 time=1751051971611934058 rawtime=208576052862 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'H'
<OUTPUT pid=67 tid=67 time=1751051971612097568 rawtime=208576216372 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'H'
<INPUT pid=2580 tid=2580 time=1751051971612342263 rawtime=208576461926 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'H'
<OUTPUT pid=67 tid=67 time=1751051971612367333 rawtime=208576487354 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'H'
<INPUT pid=2579 tid=2579 time=1751051971808898991 rawtime=208773018069 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'e'
<OUTPUT pid=67 tid=67 time=1751051971809014928 rawtime=208773134006 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'e'
<INPUT pid=2580 tid=2580 time=1751051971809320248 rawtime=208773439326 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'e'
<OUTPUT pid=67 tid=67 time=1751051971809351426 rawtime=208773471241 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'e'
<INPUT pid=2579 tid=2579 time=1751051971964705058 rawtime=208928823985 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051971964878073 rawtime=208928997000 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2580 tid=2580 time=1751051971965206444 rawtime=208929325371 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051971965235901 rawtime=208929355554 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2579 tid=2579 time=1751051972143167788 rawtime=209107286648 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051972143292895 rawtime=209107411755 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2580 tid=2580 time=1751051972143459449 rawtime=209107578309 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051972143483528 rawtime=209107602911 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2579 tid=2579 time=1751051972318556514 rawtime=209282675286 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051972318681585 rawtime=209282800357 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2580 tid=2580 time=1751051972318875590 rawtime=209282995496 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051972318899197 rawtime=209283018165 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2579 tid=2579 time=1751051972587453662 rawtime=209551572401 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b','
<OUTPUT pid=67 tid=67 time=1751051972587621515 rawtime=209551740254 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b','
<INPUT pid=2580 tid=2580 time=1751051972587734382 rawtime=209551853121 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b','
<OUTPUT pid=67 tid=67 time=1751051972587758332 rawtime=209551878383 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b','
<INPUT pid=2579 tid=2579 time=1751051972700061714 rawtime=209664180622 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b' '
<OUTPUT pid=67 tid=67 time=1751051972700188164 rawtime=209664307072 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b' '
<INPUT pid=2580 tid=2580 time=1751051972700536831 rawtime=209664655739 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b' '
<OUTPUT pid=67 tid=67 time=1751051972700565465 rawtime=209664684373 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b' '
<INPUT pid=2579 tid=2579 time=1751051972892415567 rawtime=209856535138 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'W'
<OUTPUT pid=67 tid=67 time=1751051972892541864 rawtime=209856661435 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'W'
<INPUT pid=2580 tid=2580 time=1751051972892748515 rawtime=209856868086 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'W'
<OUTPUT pid=67 tid=67 time=1751051972892776412 rawtime=209856895983 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'W'
<INPUT pid=2579 tid=2579 time=1751051973053552503 rawtime=210017672160 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051973053768028 rawtime=210017887685 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2580 tid=2580 time=1751051973053883021 rawtime=210018002678 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'o'
<OUTPUT pid=67 tid=67 time=1751051973053908007 rawtime=210018027638 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'o'
<INPUT pid=2579 tid=2579 time=1751051973140155837 rawtime=210104274616 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'r'
<OUTPUT pid=67 tid=67 time=1751051973140277309 rawtime=210104396088 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'r'
<INPUT pid=2580 tid=2580 time=1751051973140428835 rawtime=210104547614 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'r'
<OUTPUT pid=67 tid=67 time=1751051973140452038 rawtime=210104571622 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'r'
<INPUT pid=2579 tid=2579 time=1751051973250867779 rawtime=210214986547 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051973250993810 rawtime=210215112578 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2580 tid=2580 time=1751051973251331050 rawtime=210215449818 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'l'
<OUTPUT pid=67 tid=67 time=1751051973251361348 rawtime=210215480116 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'l'
<INPUT pid=2579 tid=2579 time=1751051973335770189 rawtime=210299889755 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'd'
<OUTPUT pid=67 tid=67 time=1751051973335937186 rawtime=210300056752 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'd'
<INPUT pid=2580 tid=2580 time=1751051973336218966 rawtime=210300338532 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'd'
<OUTPUT pid=67 tid=67 time=1751051973336246835 rawtime=210300366528 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'd'
<INPUT pid=2579 tid=2579 time=1751051973665644437 rawtime=210629763107 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'!'
<OUTPUT pid=67 tid=67 time=1751051973665786687 rawtime=210629905357 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'!'
<INPUT pid=2580 tid=2580 time=1751051973666070698 rawtime=210630189368 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'!'
<OUTPUT pid=67 tid=67 time=1751051973666097902 rawtime=210630217539 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'!'
<INPUT pid=2579 tid=2579 time=1751051974226180674 rawtime=211190299600 cgid=7827 inode=89 pidtgid=11076720658963 nsid=12616466428 comm=b'sshd' len=1>
b'\r'
<OUTPUT pid=67 tid=67 time=1751051974226348069 rawtime=211190466995 cgid=1 inode=0 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=1>
b'\r'
<INPUT pid=2580 tid=2580 time=1751051974226417647 rawtime=211190536573 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=1>
b'\n'
<OUTPUT pid=67 tid=67 time=1751051974226440318 rawtime=211190559951 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=2>
b'\r\n'
<INPUT pid=2580 tid=2580 time=1751051974226501433 rawtime=211190620594 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=9>
b'\x1b[?2004l\r'
<OUTPUT pid=67 tid=67 time=1751051974226556167 rawtime=211190675351 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=9>
b'\x1b[?2004l\r'
<INPUT pid=2580 tid=2580 time=1751051974227307873 rawtime=211191426669 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=14>
b'Hello, World!\n'
<INPUT pid=2580 tid=2580 time=1751051974227857480 rawtime=211191976447 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=8>
b'\x1b[?2004h'
<INPUT pid=2580 tid=2580 time=1751051974227952968 rawtime=211192071701 cgid=7827 inode=3 pidtgid=11081015626260 nsid=12616466428 comm=b'bash' len=52>
b'\x1b]0;joe@bpf: ~\x07\x1b[01;32mjoe@bpf\x1b[00m:\x1b[01;34m~\x1b[00m$ '
<OUTPUT pid=67 tid=67 time=1751051974227997645 rawtime=211192116397 cgid=1 inode=7863412966886368629 pidtgid=287762808899 nsid=12616466428 comm=b'kworker/u10:5' len=75>
b'Hello, World!\r\n\x1b[?2004h\x1b]0;joe@bpf: ~\x07\x1b[01;32mjoe@bpf\x1b[00m:\x1b[01;34m~\x1b[00m$ '
```
