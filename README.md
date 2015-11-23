# outside_domain_in_dhcp
A Powershell script to check Windows DHCP servers, warn for non-domain computers and reservation changes.

It needs that the servers are able to launch powershell and the Netsh command.
This script is ok with every DHCP server since 2003, as Powershell il available since W2003.
The computer / server that will execute this script needs to have the Active Directory module for Powershell (RSAT Tool).
Tested with Powershell V5, it will work with V4/V3, but is untested with V2 (risks of display error with the Convertto-Html cmdlet)


HOW TO....


1) To allow Powershell scripts execution, you need first to allow script execution ( :) ) . To do this, you have to open a Powershell console (as admin) and do this command : 

Set-ExecutionPolicy unrestricted -force

2) Launch for the first time the script from Powershell / Powershell ISE to anwser the configuration questions.


3) Create a scheduled task that will run Powershell with admin rights and with the PS1 path as argument.

4) After the first run, the script will create an exceptions.txt file in the directory you choose (created at point 2, and filled in config.ini). In this file, you can fill (one per line) a mac address (format sample : 44-1e-a1-57-38-d2) or an FQDN computer name (example.domain.com) to be excluded from the warning list. (In case of an outside AD but legitimate entry : Wifi, Linux computer, thin client...)

5) If you have to move the script, the .PS1 file AND the config.ini file must be in the SAME DIRECTORY.
