$scriptPath = $null
$answer = "z"
if ((Get-Host).Version.Major -le 2)
{
    $scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
}
else
{
    $scriptPath = $PSScriptRoot
}
$configfile = Join-Path $scriptPath "config.ini"
try 
{
    $configuration = Get-Content $configfile -ErrorAction Stop
}
catch
{
#region CONFIGFILECREATION

    While($answer.tolower()[0] -ne "y" -and $answer.tolower()[0] -ne "n")
    {
        $answer = Read-host "Unable to access $configfile `nWould you like to create it? (Y/N)"
    }
    if ($answer.ToLower()[0] -eq "n")
    {
        throw("Script end")
    }
    else
    {
        #region DHCPPOOLS
        $answer = "z"
        while($answer.tolower()[0] -ne "y")
        {
            $ippoolarray = @()
            $answer = "z"
            Write-Host "Choose DHCP pools, one per line. Blank line to finish."
            do 
            {
                $ippool = "Add_pools"
                while($ippool -as [System.Net.IPAddress] -isnot [System.Net.IPAddress] -and $ippool -ne "")
                {
                    $ippool = Read-Host "=>"
                }
                if ($ippool -ne "")
                {
                    Write-host "$(([System.Net.IPAddress]$ippool).Ipaddresstostring) added!"
                    $ippoolarray += $ippool
                }
            }while ($ippool -ne "")
            $ippoolarray = $ippoolarray | Sort-Object -Unique
            Write-Host "You choose :`n"
            $ippoolarray
            while ($answer.tolower()[0] -ne "y" -and $answer.tolower()[0] -ne "n")
            {
                $answer = Read-Host "Is that ok? (Y/N)"
            }

        }
        #endregion
        #region DHCPSERVERS
        $answer = "z"
        while($answer.tolower()[0] -ne "y")
        {
            $dhcpserversarray = @()
            $answer = "z"
            Write-Host "Enter DHCP server names or IP address, one per line. Blank line to finish."
            do 
            {
                $dhcpserver = "Add_server"
                while($dhcpserver -ne "")
                {
                    $dhcpserver = Read-Host "=>"
                
                    
                    if ($dhcpserver -ne "")
                    {
                        Write-host "$dhcpserver added!"
                        $dhcpserversarray += $dhcpserver
                    }
                }
            }while ($dhcpserver -ne "")
            $dhcpserversarray = $dhcpserversarray | Sort-Object -Unique
            Write-Host "You choose :`n"
            $dhcpserversarray
            while ($answer.tolower()[0] -ne "y" -and $answer.tolower()[0] -ne "n")
            {
                $answer = Read-Host "Is that ok? (Y/N)"
            }
            $answertotest = "z"
            while ($answertotest.tolower()[0] -ne "y" -and $answertotest.tolower()[0] -ne "n" -and $answer -ne "n")
            {
                $answertotest = Read-Host "Would you like to try servers connection? (Y/N)"
            }
            if ($answertotest.ToLower()[0] -eq "y")
            {
                $iserror = $false
                foreach ($server in $dhcpserversarray)
                {
                    $message = "Success!"
                    $color = "Green"
                    
                    if (!(Test-Connection $server -Count 1 -Quiet -ErrorAction Stop))
                    {
                        $iserror = $true
                        $message = "Fail! :c"
                        $color = "Red"
                    }
                    Write-host $server " => " $message -ForegroundColor $color
                }
                
                if ($iserror -eq $false)
                {
                    Write-host "Everything is ok :)"
                }
                else
                {
                    Write-Host "One or more errors happened."
                    do
                    {
                        $answer = Read-host "Continue anyway? (Y/N)"
                    }while ($answer.tolower()[0] -ne "y" -and $answer.tolower()[0] -ne "n")
                    if ($answer.tolower()[0] -eq "n")
                    {
                        throw("Script ended")
                    }
                }

            }

        }
        

        #endregion

        #region MAIL
        $answertomail = "z"
        while($answertomail.ToLower()[0] -ne "y")
        {
            do
            {
                Write-Host "Fill SMTP server name"
                $mailserver = Read-Host "=>"
                Write-Host "Enter SENDER email address"
                $from = Read-Host "=>"
                Write-Host "Enter RECIPIENT email address"
                $to = Read-Host "=>"
                $mailconfiguration = [pscustomobject]@{
                "Mailserver"=$mailserver
                "From" = $from
                "To" = $to
                } 
                $mailconfiguration | ft
                $answertomail = Read-Host "Is that ok? (Y/N)"
            }while($answertomail.ToLower()[0] -ne "y" -and $answertomail.ToLower()[0] -ne "n")
            $answertosendmail = "z"
            $mailreceived = "z"
            if ($answertomail.ToLower()[0] -eq "y")
            {
                while($answertosendmail -ne "n")
                {
                    do
                    {
                        $answertosendmail = Read-Host "Would you like to send a test email? (Y/N)"
                    } while($answertosendmail.ToLower()[0] -ne "y" -and $answertosendmail.ToLower()[0] -ne "n")
                    if ($answertosendmail.ToLower()[0] -eq "y")
                    {
                        $sendmailerror = $false
                        try
                        {
                            Send-MailMessage -From $from -To $to -Subject "Test mail from Powershell" -SmtpServer $mailserver
                        }
                        catch
                        {
                            $sendmailerror = $true
                            Write-host "Error while sending email!"
                        }
                        if ($sendmailerror -eq $false)
                        {
                            do
                            {
                                $mailreceived = read-host "Mail send. Did you received it? (Y/N)."
                            }while ($mailreceived.ToLower()[0] -ne "y" -and $mailreceived.ToLower()[0] -ne "n")
                            if ($mailreceived.ToLower()[0] -eq "n")
                            {
                                do
                                {
                                    $answertomail = Read-Host "Do you want to continue and reconfigure? (Y/N)"
                                }while ($answertomail.ToLower()[0] -ne "y" -and $answertomail.ToLower()[0] -ne "n")
                                switch ($answertomail.tolower()[0])
                                {
                                "y" { $answertomail = "n";$answertosendmail = "n" }
                                "n" { throw("No mail. Script stopped.") }
                                }
                            }
                            else
                            {
                                $answertosendmail = "n"
                            }
                        }

                    }
                }
            }
        }
        #endregion
        #region CHEMIN
        $answer = "z"
        $path = $null
        do
        {
            do
            {
                $path = Read-Host "Enter a path (local or UNC) to store script datas`n=>"
                $answerpathtest = Read-Host "Do you want to test this path :`n$path`n(Y/N) =>"
            } until ($answerpathtest.ToLower()[0] -eq "y" -or $answerpathtest.ToLower()[0] -eq "n")
            if ($answerpathtest -eq "y")
            {
                $answerpathretry = "z"
                if (Test-Path $path)   
                {
                    
                    Write-host -ForegroundColor Green "Path valid.`nWrite test."
                    $testfilename = [string](get-date).Ticks+".test"
                    $answer = "y"
                    try
                    {
                        New-Item -ItemType File (Join-Path $path $testfilename) -Force
                    }
                    catch
                    {
                        Write-Host "Unable to write here : $path `nPlease choose another folder."
                        $answer = "z"
                    }
                        Remove-Item (Join-Path $path $testfilename) -Force -ErrorAction SilentlyContinue
                }
                else
                {
                    do
                    {
                        Write-Host "Destination does not exists. Do you want to create it? (Y/N)"
                        $answerpathretry = Read-Host "=>"
                    } until ($answerpathretry.ToLower()[0] -eq "y" -or $answerpathretry.ToLower()[0] -eq "n")
                    if ($answerpathretry.ToLower()[0] -eq "n")
                    {
                        throw("Script stop")
                    }
                    $answer = "z"
                    
                }
            }
            
        } until ($answer.ToLower()[0] -eq "y" -or $answer.ToLower()[0] -eq "n")
        $answer = "z"
        do
        {
            $answer = Read-Host "Do you want to check DHCP reservations too? (Y/N)"
        } until($answer.ToLower()[0] -eq "y" -or $answer.ToLower()[0] -eq "n")
        #endregion
        $dhcprescheck = $true
        if ($answer.ToLower()[0] -eq "n")
        {
            $dhcprescheck = $false
        }
    }

    try
    {
        $configurationarray = New-Object PSCUSTOMOBJECT
        $configurationarray | Add-Member -Name pools -MemberType NoteProperty -Value $ippoolarray
        $configurationarray | Add-Member -name servername -MemberType NoteProperty -Value $dhcpserversarray
        $configurationarray | Add-Member -Name mailconfiguration -MemberType NoteProperty -Value $mailconfiguration
        $configurationarray | Add-Member -Name path -MemberType NoteProperty -Value $path
        $configurationarray | Add-Member -Name rescheck -MemberType NoteProperty -Value $dhcprescheck
    }
    catch
    {
        Write-Host -ForegroundColor Red "Error while building configuration informations. Here is the actual configuration object state :`n$configurationarray"
    }
    try
    {
        $configurationarray | Export-Clixml $configfile -ErrorAction Stop
    }
    catch
    {
        Write-Host -ForegroundColor Red "Unable to save configuration data file. The script will end."
    }
#endregion
} #end catch

$configurationarray = Import-Clixml $configfile -ErrorAction Stop

#region fichiers

    #Précisez le chemin du fichier ou seront sauvegardées les données des PC détectés
$path = $configurationarray.path
$filename = "outsidedomain.xml" #Nom a donner au fichier.
$staticfile = "staticaddress.xml" #Nom a donner au fichier.
$exceptionfile = "exceptions.txt" #Nom du fichier d'exceptions
$exceptionpath = Join-Path $path $exceptionfile 
$fullpath = Join-Path $path $filename
$staticpath = Join-Path $path $staticfile
$dateforcsv = Get-Date  -Format "yyyy_MM"
#endregion

#region DHCP
$plages = $configurationarray.pools #Plage(s) à surveiller
$servername = $configurationarray.servername #nom de serveur(s) DHCP
#endregion

#region MAIL
$from = $configurationarray.mailconfiguration.From #Adresse mail de l'expéditeur
$to = $configurationarray.mailconfiguration.To #Adresse mail du destinataire
$smtpserver = $configurationarray.mailconfiguration.Mailserver #Serveur SMTP

$encoding = [System.Text.UTF8Encoding]::UTF8 #Encodage en UTF8 pour éviter les problèmes d'accents, entre autre
#endregion

#region jobs
$maximaljobperserver = 4
#endregion

#region variables 
$computerlist = Get-ADComputer -filter *
$arraylist = New-Object System.Collections.ArrayList
$notindomainarraylist = New-Object System.Collections.ArrayList
$resultingarray = New-Object System.Collections.ArrayList
$staticresults = New-Object System.Collections.ArrayList
$staticmodified = New-Object System.Collections.ArrayList

$monitorstatic = $true
#endregion

function Report-StaticChange {
param(
[string]$Raison = "non spécifiée", 
[string]$NewIP = $null, 
[string]$OldIP = $null, 
[string]$NewMAC = $null, 
[string]$OldMAC = $null)


    $staticmodified.Add([pscustomobject]@{
    "Raison" = $Raison
    "Nouvelle_IP" = $NewIP
    "Ancienne_IP" = $OldIP
    "Nouvelle_MAC" = $NewMAC
    "Ancienne_MAC" = $OldMAC}) | Out-Null
    
}

try {
    $staticresultsprevious = Import-Clixml $staticpath
}
catch
{
    "Aucun fichier précedent d'IP reservées" 
}
try{
    $exceptions = Get-content $exceptionpath -erroraction stop
}
catch
{
    Try
    {
        New-Item -ItemType File $exceptionpath -Force
    }    
    catch
    {
        "Impossible de créer le fichier d'exception. Arrêt du script"
        Start-Sleep -Seconds 5
        throw("STOP FICHIER EXCEPT.")
    }
}

try
{
    $fichiernondomaine = Import-Clixml $fullpath
}
catch
{
    Write-Output "Aucun fichier de précedence à $fullpath, vérification du chemin."
    if (!(Test-Path $fullpath))
    {

        Write-Output "Chemin inexistant, création du fichier"
        try
        {
            New-Item -ItemType File $fullpath -Force -ErrorAction Stop
        }
        catch
        {
            Write-Output "Impossible de créer le fichier, arret du script."
            Start-Sleep -Seconds 5
            throw($error[0].Exception)
        }
    }
}


foreach($plage in $plages)
{
    foreach ($server in $servername)
    {   
        if ($monitorstatic -eq $true)
        {
            if ((get-job -Name "$server*" | Where-Object {$_.state -eq "Running"}).count -ge $maximaljobperserver)
            {
                Write-Output "Plus de $maximaljobperserver jobs actifs sur $server. En attente de la libération de jobs."
                    
                do
                {
                    Start-Sleep -Seconds 1
                } while ((get-job -Name "$server*" | Where-Object {$_.state -eq "Running"}).count -ge $maximaljobperserver)
            }

            Start-Job -Name $($server+"_"+$plage+"_static") -ScriptBlock { 
                param($plage,$server)
                $jobstaticresults = New-Object System.Collections.ArrayList
                $staticstats = Invoke-Command -computername $server -scriptblock {powershell.exe "chcp 1252;Netsh dhcp server scope $($args[0]) show reservedip"} -ArgumentList $plage 
                foreach ($entry in $staticstats) 
                {
                    if ($entry.trim() -match "(?<IP>\d+.\d+.\d+.\d+)\W+-\W+(?<MAC>\w+-\w+-\w+-\w+-\w+-\w+)")
                    {
                        $jobstaticresults.Add([PSCUSTOMOBJECT]@{
                        "IP" = $Matches.IP
                        "MAC" = $Matches.MAC
                        }) | Out-Null   
                    }
                }
                return $jobstaticresults
            } -ArgumentList $plage,$server #end start-job
        } #end if ($monitostatic -eq $true)
        if ((get-job -Name "$server*" | Where-Object {$_.state -eq "Running"}).count -ge $maximaljobperserver)
        {
            Write-Output "Plus de $maximaljobperserver jobs actifs sur $server. En attente de la libération de jobs. (leases)"
        
            do
            {
                Start-Sleep -Seconds 1
            } while ((get-job -Name "$server*" | Where-Object {$_.state -eq "Running"}).count -ge $maximaljobperserver)        
        }

        Start-Job -Name $($server+"_"+$plage+"_leases") -ScriptBlock {
            param($plage,$server)
            $jobarraylist = New-Object System.Collections.ArrayList
            $stats = Invoke-Command -computername $server -scriptblock {powershell.exe "chcp 1252;Netsh dhcp server scope $($args[0]) show clients 1"} -ArgumentList $plage
            foreach ($entry in $stats)
            {

                if ($entry.trim() -match "(?<IP>\d+.\d+.\d+.\d+.)\W+-\W+(?<MASQUE>\d+.\d+.\d+.\d+.).*?[^\w+](?<MAC>\w+-\w+-\w+-\w+-\w+-\w+).*?[^\d+](?<BAIL>\d+/\d+/\d+\s+\d+:\d+:\d+).*?[^\w+](?<TYPE>\w+).*?[^\w+](?<PC>\w+.*)$")
                {
                    $jobarraylist.Add([pscustomobject]@{
                    "IP" = $Matches.ip
                    "Masque" = $Matches.MASQUE
                    "MAC" = $Matches.MAC
                    "PC" = $Matches.PC
                    "Type" = $Matches.TYPE
                    "Date" = (get-date $Matches.Bail ) 
                    }) | Out-Null
                    
                }
            }
            return $jobarraylist
        } -ArgumentList $plage,$server #end start-job
    }
}
Get-job | Wait-Job
$joblist = Get-Job | Where-Object {$_.State -eq "Completed"}
Write-Output "Obtaining static IP"
    foreach ($job in ($joblist |Where-Object {$_.name -like "*static"}))
    {
        $value = Receive-Job $job
        if ($value -ne $null)
        {
            try
            {
                $staticresults.AddRange($value) | Out-Null
            }
            catch
            {
                try
                {
                    $staticresults.Add($value) | Out-Null
                }
                catch
                {
                    Write-Output "Error while adding datas from $($job.name) `nValue :  $($value)"
                }
            }
        }
        Remove-Job $job
    }
$joblist = Get-Job


foreach ($job in $joblist)
{
    $value = Receive-Job $job
    if ($value -ne $null)
    {
        try{
        $arraylist.AddRange($value) | Out-Null
        }
        catch
        {
            try
            {
                $arraylist.Add($value) | Out-Null
            }
            catch
            {
                Write-Output "Error while adding datas from $($job.name) `nValue :  $($value)"
            }
        }

    }
    Remove-Job $job -ErrorAction stop
}

foreach ($job in Get-Job)
{
    Write-Output "Error on $job. $Job.state"
    Receive-Job $job
}

foreach ($computer in $arraylist)
{
    $results = $arraylist | Where-Object {$_.pc -eq $computer.PC}
    foreach ($result in $results)
    {
        if ($computerlist.dnshostname -notcontains $result.pc)
        {
            "$($result.pc) unknown in AD."
            $notindomainarraylist.Add($result) | Out-Null
        }

    }
    
}
#Filtrage en fonction des exceptions. Ne garder que ce qui n'a pas d'adresse mac et de nom correspondant à la liste.
$notindomainwithexceptions = $notindomainarraylist | Where-Object {$_.MAC -notin $exceptions -and $_.PC -notin $exceptions}

if ($fichiernondomaine -ne $null)
{
    foreach ($computer in $notindomainwithexceptions)
    {
        if ($fichiernondomaine.pc.contains($computer.pc))
        {
            
            #Recherche du pc X avec l'adresse mac Y
            $results = $fichiernondomaine | Where-Object {$_.pc -eq $computer.pc -and $_.MAC -eq $computer.MAC} | Sort-Object -property ip,date -Unique
            if ($results -eq $null)
            {
                "results eq null"
                #L'ordinateur est trouvé, mais sous une autre carte réseau
                $index = $notindomainwithexceptions.pc.IndexOf($computer.pc) #changé $_.pc en $computer.pc
                $item = $notindomainwithexceptions[$index]
                $item | Add-Member -MemberType NoteProperty -Name "Raison" -Value "New network card" -force
                $resultingarray.Add($item) | Out-Null
            }
            elseif ($results.ip -contains $computer.ip)
            {
                
                #L'ordinateur est trouvé dans le DHCP, on vérifie si le bail expire à la même date.
                
                #On filtre uniquement sur l'objet ayant la même adresse que l'ordinateur

                $item = $results | Where-Object {$_.ip -eq $computer.ip}

                if ($computer.Date -gt $item.Date)
                {
                    #La valeur date est plus grande, il a donc eu un renouvellement de bail
                    $item | Add-Member -MemberType NoteProperty -Name "Raison" -Value "New DHCP Lease" -Force
                    $resultingarray.Add($item) | Out-Null
                }
                #Sinon, on enregistre pas, on avertit pas.

            }
        }
        else
        {
            #Si le fichier xml importé ne comporte pas l'ordinateur, c'est donc une nouvelle connexion
            $item = $computer
            $item | Add-Member -MemberType NoteProperty -Name "Raison" -Value "New connection" -Force
            $resultingarray.Add($item) | Out-Null

        }
    }

    $notindomainarraylist | Export-Clixml $fullpath
    
    if ($resultingarray -ne $null)
    {
        $resultingarray = $resultingarray | Select-object -property IP,Masque,Mac,PC,Type,Date,Raison
        Send-MailMessage -From $from -To $to -Subject "New connections detected" -Bodyashtml $([string]($resultingarray | ConvertTo-Html -PreContent "Type : N - AUCUN, D - DHCP B - BOOTP, U - NON SPÉCIFIÉ, R - RÉSERVATION IP" -Head "<style>  td, th  {border: 1px solid black;} table{border-spacing:0;} </style>")) -Encoding $encoding -SmtpServer $smtpserver
        $resultingarray | Export-Csv (join-path $configurationarray.path $("out_domain_"+ $dateforcsv +".csv")) -NoTypeInformation -Append -Delimiter ";" -Encoding UTF8
    }
}
else
{
    Write-Output "Aucun fichier de précedence du DHCP trouvé. Enregistrement des données actuelles en tant que reference"
    $notindomainarraylist | Export-Clixml $fullpath
}

#Gestion des IP Statiques
if ($monitorstatic -eq $true)
{
    $staticresults = $staticresults | Select-object -property IP,MAC | Sort-Object -Property "ip","mac" -Unique
    if ($staticresultsprevious -eq $null)
    {
        Write-Output "Aucun fichier de précedence des réservations trouvé. Enregistrement des données actuelles en tant que reference"
        $staticresults | Export-Clixml $staticpath
    }
    else
    {
        foreach ($entry in $staticresults)
        {
            #Si l'ip est bien dans la liste des résultats précedents...
            if ($entry.ip -in $staticresultsprevious.ip)
            {
                #On reprends l'objet de la fois précedente...
                $check = $staticresultsprevious | Where-Object {$_.ip -eq $entry.ip}
                #Si leurs macs différent, l'adresse mac a été changée
                if ($entry.MAC -ne $check.MAC)
                {
                    "Mac."
                    Report-StaticChange -Raison "Changed MAC" -OldIP $check.ip -NewIP $entry.ip -OldMAC $check.mac -NewMAC $entry.MAC
                    
                }
            }
            #Si l'ip n'est pas dans la liste des résultats précédents
            #MAIS que la MAC y est... L'IP a donc changé
            elseif ($entry.mac -in $staticresultsprevious.mac)
            {
                "ip"
                $check = $staticresultsprevious | Where-Object {$_.mac -eq $entry.mac}
                Report-StaticChange -Raison "Changed IP" -OldIP $check.ip -NewIP $entry.ip -OldMAC $check.mac -NewMAC $entry.MAC

            }
            #Si ni MAC ni IP, alors c'est une nouvelle entrée
            else
            {
                "new"
                Report-StaticChange -Raison "New entry" -OldIP $null -NewIP $entry.ip -NewMAC $entry.MAC
            }
            
        }
        #On loop et vérifie que chaque ancien résultat est toujours présent pour s'assurer que rien n'est supprimé
        foreach ($staticresultprevious in $staticresultsprevious)
        {
            #Si l'IP n'est pas dans la liste actuelle, et que la MAC n'est pas dans la liste actuelle 
            if ($staticresultprevious.ip -notin $staticresults.ip -and $staticresultprevious.mac -notin $staticresults.mac)
            {   
                #On regarde si l'adresse et la mac ne sont pas dans les dernières détections de changement MAC / IP
                #afin de ne pas marquer une entrée comme retirée alors qu'elle est simplement modifiée
                if ($staticresultprevious.ip -notin $staticmodified.ip -or $staticresultprevious.mac -notin $staticmodified.mac)
                {
                    Report-StaticChange -Raison "Removed entry" -OldIP $null -NewIP $staticresultprevious.ip -NewMAC $staticresultprevious.MAC
                }
            }

        }
        $staticresults | Export-Clixml $staticpath
        if ($staticmodified.Count -gt 0)
        {
            Send-MailMessage -From $from -To $to -Subject "DHCP reservations changed" -Bodyashtml $([string]($staticmodified | ConvertTo-Html -PreContent "List of detected modifications on DHCP reservations" -Head "<style>  td, th  {border: 1px solid black;} table{border-spacing:0;} </style>")) -Encoding $encoding -SmtpServer $smtpserver
            $staticmodified | Export-Csv (join-path $configurationarray.path $("reserved_changed_"+ $dateforcsv +".csv")) -NoTypeInformation -Append -Delimiter ";" -Encoding UTF8

        }
    }
}

