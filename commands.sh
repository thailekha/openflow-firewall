# Run this first

cd /mnt/vagrant/pox && ./pox.py log.level --DEBUG misc.firewall

# Then this in another terminal, then you're good to go

sudo killall controller || sudo mn -c && sudo mn --topo single,4 --mac --switch ovsk --controller remote
sudo killall controller || sudo mn -c && sudo mn --topo single,2 --mac --switch ovsk --controller remote

# Tests
pingall

h4 python -m SimpleHTTPServer 80 &
h3 python -m SimpleHTTPServer 80 &
h2 python -m SimpleHTTPServer 80 &
h1 python -m SimpleHTTPServer 80 &

h1 ping -c1 h2 # blocked
h2 ping -c1 h1 # blocked
h2 ping -c1 h3 # blocked
h3 ping -c1 h2 # blocked
h3 ping -c1 h4 # not blocked
h4 ping -c1 h3 # not blocked

h1 wget -O - h2
h2 wget -O - h1
h3 wget -O - h4
h4 wget -O - h3
h1 wget -O - 10.0.0.3:8080
h3 wget -O - 10.0.0.1:8080

h1 wget -O - 10.0.0.3:80 # not blocked
h3 wget -O - 10.0.0.1:80 # not blocked

iperf

# Every time you change the script, re run the commands in the exact order

# Linting
pylint pox/misc/firewall.py
autopep8 --in-place --aggressive --aggressive pox/misc/firewall.py

# Other
h1 kill %python
strace -fe open ./pox.py misc.firewall 3>&1 1>&2 2>&3 3>&- | grep -v '= -1' | grep 'open(' | cut -d\" -f2
strace -fe open ./pox.py misc.firewall 2>&1 >/dev/null | grep -v '= -1' | grep 'open(' | cut -d\" -f2
