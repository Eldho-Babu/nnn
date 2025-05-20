# nnn
alert tcp any any -> $HOME_NET 80 (flags:S; msg:"TCP SYN Flood Attempt Detected"; sid:1000001; rev:1;)
