Vagrant.configure("2") do |config|

  config.vm.define "tcptracer" do |vm|
    vm.vm.box = "ubuntu/bionic64"
    vm.vm.hostname = 'tcptracer'
    vm.vm.box_url = "ubuntu/bionic64"

    vm.vm.network :private_network, ip: "192.168.56.101"

    config.vm.synced_folder "../../../..", "/opt/stackstate-go"
    config.vm.provision :shell, path: "bootstrap.sh"

    vm.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", 1024]
      v.customize ["modifyvm", :id, "--name", "tcptracer"]
    end
  end
  
end