# -*- mode: ruby -*-
# vi: set ft=ruby :

$init = <<SCRIPT
  sudo aptitude update
  sudo DEBIAN_FRONTEND=noninteractive aptitude install -y build-essential fakeroot debhelper autoconf automake libssl-dev graphviz \
   python-all python-qt4 python-twisted-conch libtool git tmux vim python-pip python-paramiko \
   python-sphinx oracle-java8-installer
  sudo pip install alabaster
  sudo aptitude install -y openjdk-8-jdk
  echo 'export JAVA_HOME="/usr/lib/jvm/default-java"' >> ~/.profile
  source ~/.profile
SCRIPT

$mininet = <<SCRIPT
  git clone git://github.com/mininet/mininet
  pushd mininet
  git checkout -b 2.2.2 2.2.2
  ./util/install.sh -a
  popd
SCRIPT

$cleanup = <<SCRIPT
  aptitude clean
  rm -rf /tmp/*
SCRIPT

$fix_tty = <<SCRIPT
  sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.box_check_update = false
  config.vbguest.auto_update = false

  config.vm.synced_folder ".", "/mnt/vagrant"

  config.vm.provider "virtualbox" do |v|
      v.customize ["modifyvm", :id, "--cpuexecutioncap", "50"]
      v.customize ["modifyvm", :id, "--memory", "2048"]
  end

  ## Guest config
  config.vm.hostname = "sdnlab"
  config.vm.network :private_network, ip: "192.168.56.101"

  ## Provisioning
  config.vm.provision :shell, privileged: true, :inline => $fix_tty
  config.vm.provision :shell, privileged: false, :inline => $init
  config.vm.provision :shell, privileged: false, :inline => $mininet
  config.vm.provision :shell, :inline => $cleanup

  ## SSH config
  config.ssh.forward_x11 = true
end
