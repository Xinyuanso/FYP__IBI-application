# Development of Identity-Based Identification (IBI) Library
This project implements an Identity-Based Identification (IBI) scheme into cryptographic library using MIRACL Core. An application of client-server structure demonstrates the library's usage. 


## Directory Structure
- /IBI_Scheme.py
- /client
- /server
- /requirement.txt     
- /README.md


## Requirements
- Python version: 3.10
- Recommended environment: anaconda or virtualenv
- System : Tested on Linux (Server) & MacOS (Client)

## Install dependencies 
```bash
pip install -r requirements.txt
```

## MIRACL Core Setup 
This project uses MIRACL Core library for crptographic operations. Setup of the library is needed for the environment. Link : https://github.com/miracl/core

### Steps to setup MIRACL Core 
```bash
# Clone the MIRACL Core library
git clone https://github.com/miracl/core.git

# Navigate to the Python file 
cd core/python

# Run the configuration to convert the cureve to support
python config.py

#Select option 10 or others (1-13) if needed and select 0 to exit 
#After done the configuration, test if the curves works 
python test.py
```


## How to run 

Preparation : Download the client and server folder and place it in desire device or location. Make sure there are two IP addresses for the client and server in the same network (LAN). 

### 1. Run the server at Linux 
Use server.py file in server. Modify two things : 

#### - The system apth for MIRACL Core
   ```bash
   #The path should be the path for the MIRACL Core installed on server device
   #Example: 
   sys.path.append('/home/kali/Desktop/core/python')
   sys.path.append('/home/kali/Desktop/core/python/bls12381')
   ```
#### - The server's IP address on line 116
   ```bash
   #change the address to server's IP address
   #Example: 
   app.run(host='172.20.10.3', port=5000, debug=True)
   ```
   
### 2. Run the client on MacOS 
Use client.py file in client. Modify two things : 

#### - The system apth for MIRACL Core
   ```bash
   #The path should be the path for the MIRACL Core installed on client device
   #Example: 
   sys.path.append('/Users/soxinyuan/core/python')
   sys.path.append('/Users/soxinyuan/core/python/bls12381')
   ```

#### - The server's URL on line 14
   ```bash
   #change the address to server's IP address
   #Example: 
   SERVER_URL = "http://172.20.10.3:5000"
   ```

### 3. Running code 
Run the server code first then run the client and click the link provided in client to access the webpage. 


## Overall Flow 

1. Visit the /register page and enter an identity (e.g.: email) and press 'Get secret key' button.
2. Your unique secret key (s, r) will be generated and downloadable as usk.txt.
3. On the /login page, upload the usk.txt file and enter your identity to authenticate.
4. The server verifies and come back with verification status (successful and redirect to dashboard or unsuccessful).


## License

This project is for academic use only.

© 2025 Xinyuan So — Final Year Project (FYP 2).





