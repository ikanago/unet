set -e

sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -A FORWARD -o tap0 -j ACCEPT
sudo iptables -A FORWARD -i tap0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o enp1s0 -j MASQUERADE
