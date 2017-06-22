## pcap2adu

`pcap2adu` is an attempt to clone [`adudump`](http://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf). It analyzes pcap files to identify tcp sessions, following them and displaying the RTT for individual parts of the session.

### Usage
```
joe@hubboxxx ~/src/pcap2adu $ ./bin/pcap2adu go --file=./foo.pcap
====== session: 3431a054-22fa-4eec-a5e0-607cbf0070e9 =======
SYN: 1497984391.929299 192.168.1.3:50408 > 216.58.193.206:443
RTT: 1497984391.955153 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0258541107, rtt: 0.0258541107, size: 0)
SEQ: 1497984391.955264 192.168.1.3:50408 > 216.58.193.206:443
ADU: 1497984391.989216 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599172115, rtt: 0.0272850990, size: 0)
ADU: 1497984391.989223 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599241257, rtt: 0.0272920132, size: 1418)
ADU: 1497984391.989225 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599260330, rtt: 0.0272939205, size: 1418)
ADU: 1497984391.990307 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610082150, rtt: 0.0283761024, size: 1418)
ADU: 1497984391.990314 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610151291, rtt: 0.0283830166, size: 205)
ADU: 1497984391.990408 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0611090660, rtt: 0.0000939369, size: 205)
ADU: 1497984392.001948 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0726490021, rtt: 0.0116338730, size: 205)
ADU: 1497984392.002007 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0727081299, rtt: 0.0116930008, size: 205)
ADU: 1497984392.002007 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0727081299, rtt: 0.0116930008, size: 205)
ADU: 1497984392.029228 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0999290943, rtt: 0.0272209644, size: 0)
ADU: 1497984392.029233 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0999341011, rtt: 0.0272259712, size: 51)
ADU: 1497984392.029361 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1000621319, rtt: 0.0001280308, size: 51)
ADU: 1497984392.030107 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1008079052, rtt: 0.0008738041, size: 51)
ADU: 1497984392.094131 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.1648321152, rtt: 0.0640242100, size: 622)
ADU: 1497984392.122156 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.1928572655, rtt: 0.0920493603, size: 0)
ADU: 1497984392.094255 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1649563313, rtt: 0.0001242161, size: 622)
ADU: 1497984392.094729 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1654300690, rtt: 0.0005979538, size: 622)
ADU: 1497984392.095008 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1657090187, rtt: 0.0008769035, size: 622)
ADU: 1497984392.122264 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1929652691, rtt: 0.0281331539, size: 622)
FIN: 1497984392.095008 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1657090187, rtt: 0.0002789497)
```
*above is an https request/response*

#### References
* http://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf
* https://www.mjkranch.com/docs/CODASPY17_Kranch_Reed_IdentifyingHTTPSNetflix.pdf
* http://www.cs.rice.edu/~eugeneng/inm08/presentations/Terrell.pdf
* http://www.cs.unc.edu/~jeffay/papers/SIGMETRICS-01.pdf
* http://www.cs.unc.edu/~jeffay/talks/SIGMETRICS-01-slides.pdf

#### Caveats

This relies on pcap timestamps and their ordering so in some cases (retransmits, etc) it probably won't work right.
