#!/bin/bash

# About the script: This script sets up Elasticsearch Server 9.2.1 on a Debian-based system. It adds the necessary GPG key and repository, installs Elasticsearch, and enables the service. Additionally, it resets the password for the 'elastic' user (default user).

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

sudo apt-get install apt-transport-https

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list

sudo apt-get update && sudo apt-get install elasticsearch -y

wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.2.1-amd64.deb
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.2.1-amd64.deb.sha512
shasum -a 512 -c elasticsearch-9.2.1-amd64.deb.sha512
sudo dpkg -i elasticsearch-9.2.1-amd64.deb

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service --now

sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
sudo systemctl restart elasticsearch.service