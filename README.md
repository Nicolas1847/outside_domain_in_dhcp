# outside_domain_in_dhcp
A Powershell script to check Windows DHCP servers, warn for non-domain computers and reservation changes.

It needs that the servers are able to launch powershell and the Netsh command.
This script is ok with every DHCP server since 2003, as Powershell il available since W2003.
The computer / server that will execute this script needs to have the Active Directory module for Powershell (RSAT Tool).
Tested with Powershell V5, it will work with V4/V3, but is untested with V2 (risks of display error with the Convertto-Html cmdlet)
