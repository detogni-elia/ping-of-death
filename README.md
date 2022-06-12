# ping-of-death
A Ping of Death implementation to crash (very) old Windows 95 machines and similar vulnerable systems

## How to use
./pod [spoofed_source_ip] [target_ip] [number_of_retries]  
  
The tool shall send number_of_retries very large packets to the target IP, also attempting to spoof the source IP.  
It should be noted that this may not work outside of a local network as nodes may drop the last fragment as it contains an illegal combination of Fragment offset and payload length.  

## How it works

IP fragmentation can lead vulnerable systems to buffer overflows when attempting to reconstruct fragmented IP packets.  

The Fragment_offset field in the IP header indicates where the payload of the current fragment needs to be positioned in order to reconstruct the original large payload. This field however can represent a maximum offset of 65528 while the maximum length of an IP packet can be 65535. The maximum payload size for a fragment with offset 65528 would therefore be only 7 bytes, but vulnerable systems do not perform this check and end up reconstructing the payload
from the fragments they receive in a buffer that's 65535 bytes and no more. Many at the time did not expect to receive an IP packet larger than the legal amount. This payload ends up overflowing the buffer and can create freezes and crashes.  

This implementation overflows the target system for 405 bytes
