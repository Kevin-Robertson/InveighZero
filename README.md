![InveighZero_logo](https://user-images.githubusercontent.com/5897462/62184518-7ab31380-b32c-11e9-9470-b3f482bd4577.png)

InveighZero is a C# LLMNR/NBNS/mDNS/DNS/DHCPv6 spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system. This version shares many features with the PowerShell version of [Inveigh](https://github.com/Kevin-Robertson/Inveigh).         

## Privileged Mode Features (elevated admin required)  
* SMB capture - packet sniffer based  
* LLMNR spoofer - packet sniffer based  
* NBNS spoofer - packet sniffer based  
* mDNS spoofer - packet sniffer based  
* DNS spoofer - packet sniffer based  
* DHCPv6 spoofer - packet sniffer based  
* Pcap output - TCP and UDP packets  
* Packet sniffer console output - SYN packets, SMB kerberos negotiation, etc  

## Unprivileged Mode Features
* LLMNR spoofer - UDP listener based  
* NBNS spoofer - UDP listener based  
* mDNS spoofer - UDP listener based  
* DNS spoofer - UDP listener based  
* DHCPv6 spoofer - UDP listener based  
* Note: The NBNS spoofer should work on all systems even with NBNS enabled. The LLMNR and mDNS spoofers seem to work on Windows 10 and Server 2016 with those services already enabled. Firewalls can still get in the way of everything.    

## Other Features  
* HTTP capture - TCP listener based  
* Proxy auth capture - TCP listener based  

## Notable Missing Features   
* ADIDNS attacks  
* HTTP to SMB Relay  
* HTTPS listener  
* Kerberos kirbi output  

## Notable Differences   
* Capture and log data can be imported from previous output files. The PowerShell version stores data in a global variable that persists within the PowerShell instance.  
* InveighZero does not execute in the background. Instead, a console is accessible while InveighZero is running. The console has commands that have similar functionality to Inveigh's Get-Inveigh, Watch-Inveigh, and Stop-Inveigh support functions.  

## Minimum .NET Version
3.5  

## Parameters  
In most cases, when present, the InveighZero [parameters](https://github.com/Kevin-Robertson/InveighZero/wiki/Parameters) mirror Inveigh's [parameters](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters).    

## Why The Zero In The Name?  
Inveigh started as a C# proof of concept before I switched over to PowerShell. The "Zero" is just a reference to the fact that the C# version sort of existed before the PowerShell version. Mainly though, I just needed a unique repo name.       

## Usage

* Execute with default settings  
`Inveigh.exe`

* Set primary IP   
`Inveigh.exe -IP 192.168.1.1`

* Send spoofed traffic to another system   
`Inveigh.exe -IP 192.168.1.1 -SpooferIP 192.168.1.2`

* Pcap output for HTTP and SMB   
`Inveigh.exe -Pcap Y -PcapTCP 80,445`

## Screenshots  
![InveighZero](https://user-images.githubusercontent.com/5897462/62214923-fc7a5f80-b373-11e9-968e-827da67df654.PNG)
![InveighZero_Console](https://user-images.githubusercontent.com/5897462/62178860-80066300-b318-11e9-9799-90428c08d087.PNG)
