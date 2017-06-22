## pcap2adu

`pcap2adu` is an attempt to clone [`adudump`](http://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf). It analyzes pcap files to identify tcp sessions, following them and displaying the RTT for individual parts of the session.

### Usage
```
joe@hubboxxx ~/src/abtdump $ ./bin/pcap2adu go --file=./foo.pcap
====== session: 4a284833-7981-4e77-a015-bad8c4156c09 =======
SYN: 1497984391.929299 192.168.1.3:50408 > 216.58.193.206:443
RTT: 1497984391.955153 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.0258541107, size: 0, rtt: 0.0258541107)
ADU: 1497984391.989216 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599172115, size: 0, rtt: 0.0272850990)
ADU: 1497984391.989223 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599241257, size: 1418, rtt: 0.0272920132)
ADU: 1497984391.989225 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0599260330, size: 1418, rtt: 0.0272939205)
ADU: 1497984391.990307 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610082150, size: 1418, rtt: 0.0283761024)
ADU: 1497984391.990314 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0610151291, size: 205, rtt: 0.0283830166)
ADU: 1497984392.029228 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0999290943, size: 0, rtt: 0.0272209644)
ADU: 1497984392.029233 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.0999341011, size: 51, rtt: 0.0272259712)
ADU: 1497984392.094131 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.1648321152, size: 622, rtt: 0.0640242100)
ADU: 1497984392.122156 192.168.1.3:50408 < 216.58.193.206:443 (elapsed_time: 0.1928572655, size: 0, rtt: 0.0920493603)
FIN: 1497984392.095008 192.168.1.3:50408 > 216.58.193.206:443 (elapsed_time: 0.1657090187, size: 0, rtt: 0.0002789497)
```
*above is an https request/response*

#### References
* http://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf
* https://www.mjkranch.com/docs/CODASPY17_Kranch_Reed_IdentifyingHTTPSNetflix.pdf
* http://www.cs.rice.edu/~eugeneng/inm08/presentations/Terrell.pdf
* http://www.cs.unc.edu/~jeffay/papers/SIGMETRICS-01.pdf
* http://www.cs.unc.edu/~jeffay/talks/SIGMETRICS-01-slides.pdf
