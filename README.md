# Real Time DDoS Detection with ML/AI and Mitigation with XDP/eBFP  
  
### Pre-requisites:
These pre-requisites assume you are running WSL2 and you have root access to the system (but can also work on any linux distro with minimal adjustments).  
[ ] Use apt to update and upgrade your system.  
[ ] Install tshark  
[ ] configure XDP/eBFP using the guide from this link: https://github.com/xdp-project/xdp-tools  
[ ] Install xdp-filter utility  
[ ] Install Python3
[ ] Create a python virtual environment and install dependencies from requirements.txt  
  
### Runing the tool:  
```
git clone <this repo>
cd real_time_detection
source <name_of_your_venv>/bin/activate
pip install -r requirements.txt
sudo $VIRTUAL_ENV/bin/python3 main.py --iface eth0 --duration 120
```  
