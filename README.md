# nnn
alert tcp any any -> $HOME_NET 80 (flags:S; msg:"TCP SYN Flood Attempt Detected"; sid:1000001; rev:1;)
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

sudo /usr/sbin/snort -A console -i enp0s3 -c /etc/snort/snort.conf

sudo snort -T -i enp0s3 -c /etc/snort/snort.conf
sudo hping3 -S -p 80 --flood 10.0.2.15
