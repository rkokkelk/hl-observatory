#Docker Instance setup script over SSH - tested
apt-get update && apt-get install -y docker.io
docker pull v6nerd/hl-observatory:latest && docker run -i v6nerd/hl-observatory:latest /bin/bash
cat ./results/*.json && exit
