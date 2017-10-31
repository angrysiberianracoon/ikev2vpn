# IKEv2 VPN Server from Docker image
## Description
With this project, you can deploy your own secure VPN server with support for client management and localization through a convenient console menu.

## Features
* Easy installation via Docker
* Configuration via a convenient console menu
* Adding, ban, re-issuing certificates for clients
* Localization support

## Restrictions
* Only the IP address is supported as the server address
* Authorization of clients only through certificates

## Prerequisites
* Server with Docker installed and Internet access
* External IP address for this server
* Access the Server via ssh

## Installation
Run the Docker image deployment command on the server:

```Bash
docker run -d --restart=always --cap-add=NET_ADMIN --net=host --privileged -p 8080 -p 500:500/udp -p 4500:4500/udp --name=ikev2vpn angrysiberianracoon/ikev2vpn
```

## Server configuration
To configure, run the command:
```Bash
docker exec -it ikev2vpn python /data/bin/vpn.py
```
The command opens the console server setup menu, through which you can perform the initial configuration, add, ban and update client certificates.

## Download certificates
You can obtain certificates for clients in two ways:

### 1. Getting the certificate archive through a browser
By selecting the appropriate menu item, you can download the certificates by reference.  
After sending to the console "y" the web server will stop working, the archive will be deleted.  
It's fast, but not the safest way to obtain a certificate.

### 2. Getting certificates through console output
This is a safe, but difficult way to get certificates. 
You need to copy the contents of the certificates into 3 files with specific names.  
After creating the files, you need to generate a PKCS#12 format certificate using the command that the console will give you. 

## Assigning certificates

### ca.cer
Root certificate.
It must be installed on the client device in the root certificate store.

### (client_name).cer
Client certificate.
Required to specify as a client certificate in NetowrkManager (Linux) and to generate a PKCS#12 format certificate.

### (client_name).key
The private key is the client certificate.
Required to specify the client certificate as the key in NetowrkManager (Linux) and to generate a PKCS#12 format certificate.

### (client_name).p12
Certificate format PKCS#12.
Used to authorize a client in Windows / Android.

## Supported client devices
`Windows`: 10  
`Ubuntu `: 17.04 (with NetworkManager)  
`Android`: 6 (with strongSwan app)  
`Mac`:	not tested  
`iOS`:	not tested 

If you have successfully used other devices or programs to connect to VPN, please notice me.

## Localization
If you want to add your localization to the project, send a .po file to my email or make a pull request.

## Author
Angry Siberian Racoon   
e-mail: angrysiberianracoon@gmail.com

## License
Copyright (c) 2017 Angry Siberian Racoon, this software is licensed under [MIT License](https://github.com/angrysiberianracoon/ikev2vpn/blob/master/LICENSE).