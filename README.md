## pcap2adu

`pcap2adu` is an attempt to clone [`adudump`](http://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf). It analyzes pcap files to identify tcp sessions, following them and displaying the RTT for individual parts of the session.

### Usage
```
joe@hubboxxx ~/src/pcap2adu $ ./bin/pcap2adu go --file=./foo.pcap
====== session: 5ef407d0-7324-421b-983e-e1c18e708ded =======
SYN: 1497984391.929299 192.168.1.3:50408 > 216.58.193.206:443
RTT: 1497984391.955153 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0258541107, rtt: 0.0258541107, size: 0)
SEQ: 1497984391.955264 192.168.1.3:50408 > 216.58.193.206:443
ADU: 1497984391.961931 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0326321125, rtt: 0.0066668987, size: 194)
ADU: 1497984391.989223 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599241257, rtt: 0.0339589119, size: 1418)
ADU: 1497984391.989225 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599260330, rtt: 0.0339608192, size: 1418)
ADU: 1497984391.990307 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610082150, rtt: 0.0350430012, size: 1418)
ADU: 1497984391.990314 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610151291, rtt: 0.0350499153, size: 205)
ADU: 1497984392.001948 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0726490021, rtt: 0.0115399361, size: 75)
ADU: 1497984392.002007 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0727081299, rtt: 0.0115990639, size: 6)
ADU: 1497984392.002007 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0727081299, rtt: 0.0115990639, size: 45)
ADU: 1497984392.029233 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0999341011, rtt: 0.0739688873, size: 51)
ADU: 1497984392.030107 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1008079052, rtt: 0.0007457733, size: 103)
ADU: 1497984392.094131 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.1648321152, rtt: 0.1388669014, size: 622)
ADU: 1497984392.094729 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1654300690, rtt: 0.0004737377, size: 31)
ADU: 1497984392.122264 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1929652691, rtt: 0.0280089378, size: 31)
END: 1497984392.125286 216.58.193.206:443 > 192.168.1.3:50408 (elapsed_time: 0.1959869862)
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
