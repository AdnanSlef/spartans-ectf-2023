# 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)
This repository contains an example reference system for MITRE's 2023 Embedded System CTF
(eCTF) - see https://ectf.mitre.org/ for details. This code is incomplete, insecure, and 
does not meet MITRE standards for quality.  This code is being provided for educational 
purposes to serve as a simple example that meets the minimum functional requirements for 
the 2023 eCTF.  Use this code at your own risk!

## Running and debugging
```bash
docker build -t ectf-dev -f .\docker_env\build_image.Dockerfile . 

mkdir out # Create directory to bind to docker for storing output binaries

docker run --mount type=bind,source="$(pwd)"/out,destination=/out -d -t ectf-dev 
# Get container id by running docker ps
# Copy the source directory to the container
docker cp . container-id:/spartans-ectf-2023

# Run the container
docker exec -it container-id /bin/bash
cd /spartans-ectf-2023/ # in container

# Create secrets (simulating build.depl which would create a volume for this directory)
mkdir /secrets
echo "SECRET!" > /secrets/global_secrets.txt
python3 deployment/gen_host_secrets.py --secrets-dir=/secrets

# To edit files inside container, Run VSCode with Dev Containers extension and use "Attach to a running container"

# Example of building a car
cd car
make car CAR_ID=123 BIN_PATH=/out/testcar1.bin SECRETS_DIR=/secrets ELF_PATH=/out/testcar1.elf EEPROM_PATH=/out/testcar1.eeprom

docker stop container_id

# Run again
docker start container_id
docker exec -it container-id /bin/bash
```

## Design Structure
- `car` - source code for building car devices
- `deployment` - source code for generating deployment-wide secrets
- `docker_env` - source code for creating docker build environment
- `fob` - source code for building key fob devices
- `host_tools` - source code for the host tools

## Creating Your Own Fork
We suggest you create a fork of this repo so that you can begin to develop
your solution to the eCTF. To do this, you must fork the repo, change your
fork to the `origin`, and then add the example repo as another remote.
Follow these steps below.

1. Clone the eCTF repository using ssh or https 
```bash
git clone https://github.com/mitre-cyber-academy/2023-ectf-insecure-example --recurse-submodules
``` 

2. Change the current origin remote to another name
```bash
git remote rename origin example
```

3. Fork the example repo on github or create a repository on another hosting service.
   **You probably want to make the repo private for now so that other teams
   cannot borrow your development ideas** 

4. Add the new repository as the new origin
```bash
git remote add origin <url>
```

You can now fetch and push as you normally would using `git fetch origin` and
`git push origin`. If we push out updated code, you can fetch this new code
using `git fetch example`.
