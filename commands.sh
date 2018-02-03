# Run this first

cd /mnt/vagrant/pox && ./pox.py log.level --DEBUG misc.firewall

# Then this in another terminal, then you're good to go

sudo killall controller || sudo mn -c && sudo mn --topo single,4 --mac --switch ovsk --controller remote

# HTTP

h2 python -m SimpleHTTPServer 80 &
h1 wget -O - h2
h1 kill %python

# Every time you change the script, re run the commands in the exact order

# Other
strace -fe open ./pox.py misc.firewall 3>&1 1>&2 2>&3 3>&- | grep -v '= -1' | grep 'open(' | cut -d\" -f2
strace -fe open ./pox.py misc.firewall 2>&1 >/dev/null | grep -v '= -1' | grep 'open(' | cut -d\" -f2