#!/bin/bash


echo "Updating system and installing necessary packages..."
sudo apt-get update
sudo apt-get install -y python3
sudo apt-get install python3-pip
sudo apt-get install iptables
sudo apt-get install iptables-persistent
sudo apt-get install net-tools


echo "Installing psutil for Python..."
pip3 install psutil


echo "Creating log file..."
touch iptables_manager.log


echo "Checking installations..."


if ! command -v python3 &> /dev/null
then
    echo "python3 could not be installed. Please install it manually."
    exit 1
else
    echo "python3 installed successfully."
fi

if ! command -v pip3 &> /dev/null
then
    echo "pip3 could not be installed. Please install it manually."
    exit 1
else
    echo "pip3 installed successfully."
fi


if ! command -v iptables &> /dev/null
then
    echo "iptables could not be installed. Please install it manually."
    exit 1
else
    echo "iptables installed successfully."
fi


if ! command -v netfilter-persistent &> /dev/null
then
    echo "netfilter-persistent could not be installed. Please install it manually."
    exit 1
else
    echo "netfilter-persistent installed successfully."
fi


python3 -c "import psutil" 2> /dev/null
if [ $? -ne 0 ]; then
    echo "psutil could not be installed. Please install it manually."
    exit 1
else
    echo "psutil installed successfully."
fi


if ! command -v ifconfig &> /dev/null
then
    echo "ifconfig could not be found. Please install it manually."
    exit 1
else
    echo "ifconfig found successfully."
fi

echo "All installations completed successfully. You can now run your Python script with 'sudo python3 easy_iptables.py'."