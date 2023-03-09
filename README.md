# 2023 MITRE eCTF Challenge: Protected Automotive Remote Entry Device (PARED)
# By the Michigan State University Spartans
## Spartan State Security Team
## Adrian Self, Udbhav Saxena, Michael Umanskiy, Felipe Marques Allevato
## Faculty Advisor: Dr. Qiben Yan
This repository contains our team's design for MITRE's 2023 Embedded System CTF
(eCTF) - see https://ectf.mitre.org/ for details.


## Design Structure
- `car` - source code for building secure car devices
- `deployment` - source code for generating deployment-wide secrets
- `docker_env` - source code for creating docker build environment
- `fob` - source code for building secure key fob devices
- `host_tools` - source code for the host tools