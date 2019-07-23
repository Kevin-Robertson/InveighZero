# **InveighZero**

C# version of Inveigh. This is under development and currently missing a lot of features. I've done very little testing with this so use caution.

## Current Features
* DNS Spoofer    
* LLMNR spoofer  
* mDNS Spoofer  
* NBNS spoofer (priv and unpriv)  
* HTTP challenge/response capture  
* Proxy challenge/response capture  
* SMB challenge/response capture  

## Usage

* Execute with default settings  
`Inveigh.exe`

* Set primary IP   
`Inveigh.exe -IP 192.168.1.1`

* Send spoofed traffic to another system   
`Inveigh.exe -IP 192.168.1.1 -SpooferIP 192.168.1.2`

Once Inveigh is running, additional commands are accessable through the console by pressing escape. Type 'help' or '?' for a list of commands.  