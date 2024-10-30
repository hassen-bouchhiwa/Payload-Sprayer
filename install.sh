#!/bin/bash

sudo apt update && sudo apt upgrade -y

echo "Installing Python2 and pip2..."
sudo apt install -y python2
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py

echo "Installing snapd..."
sudo apt install -y snapd
sudo systemctl enable --now snapd.socket

echo "Installing SQLMap..."
if ! sudo apt install -y sqlmap; then
    echo "Apt installation failed, installing SQLMap using pip2..."
    sudo pip2 install sqlmap
fi

echo "Installing Dalfox using snap..."
sudo snap install dalfox
sudo systemctl enable --now snapd
sudo snap enable dalfox

echo "Cloning tplmap from GitHub to the current directory..."
git clone https://github.com/epinna/tplmap.git ./tplmap
chmod +x ./tplmap/tplmap.py

echo "Installing Commix..."
if ! sudo apt install -y commix; then
    echo "Apt installation failed, installing Commix using pip2..."
    sudo pip2 install commix
fi

# Final message
echo -e "\nInstallation complete! Please take a look at config.json and update what needs to be updated."
