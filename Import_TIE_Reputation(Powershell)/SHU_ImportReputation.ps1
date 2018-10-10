<#####################################################################################
 # File: SHU_ImportReputation.ps1
 # Description: Motitors file changes in a given folder recursively. Imports file reputations to TIE-Server via WebRequest
 # Created by Andrei Oleinikow
 # Version 1.0
 # Copyright (c) Systemhaus-Ulm gmbH, 2018
 #####################################################################################>

# before starting close all registered events
Unregister-Event -SourceIdentifier *

# initialize variables
# set epo-server name or IP address
$EpoServer = '172.16.242.52'
# path to folder to be watched
$PathToReputationShareFolder = '\\s-prod-file01\SHU-Abteilungen\SHU-Scratch\TestReputation'
# path to log-file
$ErrLogPath = $PSScriptRoot + '\SHU_ImportReputationError.log'
# path to copy away folder
$PathToCopyAwayFolder = '\\s-prod-file01\SHU-Abteilungen\SHU-Scratch\moved'
# set your reputation level
$filereputation = '50'
# to set reputation comment see ProcessReputation function

# set extensions, you wants to monitor. comma-separated. use of *.* or asterisk in filenames is not allowed.
$extensionfilter = @('.exe','.dll','.bat')
# create arry list to store file watcher events
$EventsArrayList=New-Object System.Collections.ArrayList

# announce name-spaces
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web

# disable ssl certificate checks, in case TIE-Server ssl certificate is not in trusted root certification authorities
Write-host "Disable Certificate checks"
Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@
[ServerCertificateValidationCallback]::Ignore();


# add suitable table ssl protocols to avoid transfer errors
$AllProtocols = [System.Net.SecurityProtocolType] 'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# set error-level
$errorcode = 0


# create a log-file, if not exists. Use same folder as for script.
if (-not (Test-Path $ErrLogPath)) 
{
    New-Item -Path $ErrLogPath -ItemType file

}

# begin
$Message = (Get-Date -Format g) + " Starting monitoring."
Add-Content -Path $ErrLogpath -Value $Message

# check for $PathToReputationShareFolder 
try
{
    # should be set globaly to be seen by filesystemwatcher
    $global:Path = Resolve-Path($PathToReputationShareFolder) -ErrorAction Stop
}
catch
{
    # write to error-log
    Write-Host "Path" $PathToReputationShareFolder "do not exists"

    $Message = (Get-Date -Format g) + " Path " + $PathToReputationShareFolder + " do not exists."
    Add-Content -Path $ErrLogPath -Value $Message

    $Message = (Get-Date -Format g) + " Terminating Script."
    Add-Content -Path $ErrLogpath -Value $Message
    # terminate on failure
    exit
}

# check for $PathToCopyAwayFolder 
try
{
    
    Resolve-Path($PathToCopyAwayFolder) -ErrorAction Stop
}
catch
{
    # write to error-log
    Write-Host "Path" $PathToCopyAwayFolder "do not exists"

    $Message = (Get-Date -Format g) + " Path " + $PathToCopyAwayFolder + " do not exists."
    Add-Content -Path $ErrLogPath -Value $Message

    $Message = (Get-Date -Format g) + " Terminating Script."
    Add-Content -Path $ErrLogpath -Value $Message
    # terminate on failure
    exit
}

Write-Host $PathToReputationShareFolder
#exit


# filter for filesystemwatcher
# wildcards can be used (E.g. *.log | er*.*g | erro*.l*g | etc. ) only one value can be set, there is no possibility to use several values
# so we set it to * and use our own filter function
$Filter = '*.*' 

# initialize FileSystemWatcher and start watching
$FSW = new-object system.io.filesystemwatcher # create FileSystemWatcher
$FSW.Path = $PathToReputationShareFolder # set folder to be watched
$FSW.IncludeSubdirectories = $True # subderictories enclude? : True!
#$FSW.NotifyFilter = [System.IO.NotifyFilters]::LastWrite
$FSW.EnableRaisingEvents = $false
$FSW.Filter = $Filter # set filter

# function out_Text() must be defined globally, cause of EventWatcher
function global:out_Text($txt)
{ 
    Write-Host („{0}“ -f $txt) 
    Add-Content -Path $ErrLogpath -Value $txt
}

# in order to import reputation only once, check if create,- change,- rename events are for the same file. delete if found.
function global:CheckFilterEventType()
{
    $length = $EventsArrayList.count
    # go through event list, check event-type and file extension, call ProcessReputation function.
    for($i = 0; $i -lt $length; $i++)
    {
       $eventI = $EventsArrayList[$i]
       #write-host $eventI.ChangeType

       # check file is pass $extensionfilter, if not delete events from $EventsArrayList
       if($extensionfilter -contains (Get-Item $eventI.FullPath).Extension)
       {
            #do process
            Write-Host 'Check: '  $eventI.FullPath
            # call function  
            Write-Host 'Process for: '  $eventI.FullPath
            ProcessReputation($eventI)
            # remove all events for this file
            for($k = 0; $k -lt $length; $k++)
            {
                if($eventI.FullPath -eq $EventsArrayList[$k].FullPath)
                {
                    $eventK = $EventsArrayList[$k]
                    #Write-Host 'Remove: ' $eventK.FullPath 'k: ' $k
                    $EventsArrayList.RemoveAt($k)
                    #ensure next loop is possible before removed item
                    if($i -gt 0) 
                    {
                        $i--
                    }
                    if($k -ge 0) 
                    {
                        $k--
                    }
                    if($length -gt 0) 
                    {
                        $length--
                    }
                }

             }

       }
       else
       {
           # delete events from $EventsArrayList
           for($l = 0; $l -lt $length; $l++)
           {
               if($eventI.FullPath -eq $EventsArrayList[$l].FullPath)
               {
                   $eventL = $EventsArrayList[$l]
                   #Write-Host 'Remove: ' $eventL.FullPath 'l: ' $l
                   $EventsArrayList.RemoveAt($l)
                   if($i -gt 0) 
                   {
                       $i--
                   }
                   if($l -ge 0) 
                   {
                       $l--
                   }
                   if($length -gt 0) 
                   {
                       $length--
                   }
               }

            }

       }

    }
    #Write-Host 'End: ' $EventsArrayList.Count

}


function global:ProcessReputation($eventArgs)
{
  # calculate file hashes
  Write-Host $eventArgs.FullPath
  
  #get file hashes. they should be as decimal encoded byte array
  $md5 = Convert-HashToByteArray((Get-FileHash -Path $eventArgs.FullPath -Algorithm MD5).Hash)
  $md5Base64 = [System.Convert]::ToBase64String($md5)
  $sha1 = Convert-HashToByteArray((Get-FileHash -Path $eventArgs.FullPath -Algorithm SHA1).Hash)
  $sha1Base64 = [System.Convert]::ToBase64String($sha1)
  $sha2 = Convert-HashToByteArray((Get-FileHash -Path $eventArgs.FullPath -Algorithm SHA256).Hash)
  $sha2Base64 = [System.Convert]::ToBase64String($sha2)
	
  #$filereputation = '50'
  # here you can define your reputation comment
  $reputationcomment = 'Importdate: ' + (Get-Date -Format g)
  
  # send web-request
  $imported = ImportReputation $md5Base64 $sha1Base64 $sha2Base64 (Split-Path -Path $eventArgs.Name -Leaf) $reputationcomment $filereputation

  # move file to $PathToCopyAwayFolder if ImportReputation successful. Rename if needed
  if($imported -eq 0)
  {
      #Move-Item -Path $eventArgs.FullPath -Destination $PathToCopyAwayFolder
      $num = 0
      $files = Get-ChildItem -Path $PathToCopyAwayFolder -Filter *.*
      # check there are no files in destination folder, otherwise check for files with same filename->rename file
      if( $files.length -eq 0 )
      {
        Move-Item -Path $eventArgs.FullPath -Destination $PathToCopyAwayFolder
        Write-Host "move file to: " $PathToCopyAwayFolder(Split-Path -Path $eventArgs.Name -Leaf)
        $Message = (Get-Date -Format g) + " move file to: " + $PathToCopyAwayFolder + (Split-Path -Path $eventArgs.Name -Leaf)
        Add-Content -Path $ErrLogpath -Value $Message
      }
      else
      {

          $nextName = Join-Path -Path $PathToCopyAwayFolder -ChildPath (Split-Path -Path $eventArgs.Name -Leaf)
          if( Test-Path($nextName))
          {
            while(Test-Path -Path $nextName)
            {
                   $nextName = Join-Path $PathToCopyAwayFolder ((Get-Item $eventArgs.FullPath).BaseName + "_$num" + (Get-Item $eventArgs.FullPath).Extension)    
                   $num+=1   
            }
            Move-Item -Path $eventArgs.FullPath -Destination $nextName
            Write-Host "move file to: " $nextName
            $Message = (Get-Date -Format g) + " move file to: " + $nextName
            Add-Content -Path $ErrLogpath -Value $Message
          }
          else
          {
            Move-Item -Path $eventArgs.FullPath -Destination $PathToCopyAwayFolder
            Write-Host "move file to: " $PathToCopyAwayFolder(Split-Path -Path $eventArgs.Name -Leaf)
            $Message = (Get-Date -Format g) + " move file to: " + $PathToCopyAwayFolder + (Split-Path -Path $eventArgs.Name -Leaf)
            Add-Content -Path $ErrLogpath -Value $Message
          }
      }
   }
   else
   {
        # do not move file
        Write-Host "error in importing reputation"
        $Message = (Get-Date -Format g) + " error in importing reputation. Do not move file"
        Add-Content -Path $ErrLogpath -Value $Message
   }
}

# this function send web-request to the epo server
function global:ImportReputation([String]$md5, [String]$sha1, [String]$sha2, [String]$filename, [String]$comment, [String]$rep)
{
    $errorcode = 0
    Write-Host "importing reputation."
	Add-Content -Path $ErrLogpath -Value "importing reputation."
    # set url for web api, you need firs an user security tocken for your session
    $url = "https://" + $EpoServer + ":8443/remote/core.getSecurityToken.do?"
    
    $myJson = -join('[{"sha1":','"',$sha1,'"',',"md5":','"',$md5,'"',',"sha256":','"',$sha2,'"',',"reputation":','"',$rep,'"',',"comment":','"',$comment,'"',',"name":','"',$filename,'"','}]')       

    # set credentials, use salt key option if you don't want to have password as plain text
    $secpasswd = ConvertTo-SecureString "PasswordXYZ" -AsPlainText -Force
    [System.Management.Automation.PSCredential] $cred = New-Object System.Management.Automation.PSCredential ("tieautoimport",$secpasswd)
    $cred.Password

    # send web-request, get session token
	try {
		$request = invoke-webrequest -credential $cred -uri $url -UseBasicParsing
		$returncode = $request.StatusCode
	}
	catch {
		Write-host $_.Exception.Message
		Add-Content -Path $ErrLogpath -Value $_.Exception.Message
		$errorcode = -1
	}

    Write-Host $returncode

    if($returncode -eq 200)
    {
        Write-Host "EPO-Connection successfull."
 
        $token = $request.ToString().Split()[2]
        $reputationUrlEncoded = [System.Web.HttpUtility]::UrlEncode($myJson)

        # build url for setReputations request
        $url = "https://" + $EpoServer + ":8443/remote/tie.setReputations.do?:output=json&orion.user.security.token=" + $token + "&param1=" + $reputationUrlEncoded
        Write-Host $url
        
        # send web-request, set reputation
        $request = invoke-webrequest -credential $cred -uri $url -UseBasicParsing
        $returncode = $request.StatusCode
		# check if response is successfull. if you request an EpoServer with other LCID installed then english or german, accommodate response string to your language.
        if(($request -match '1 Datei-Reputationen und 0 Zertifikat-Reputationen wurden erfolgreich festgelegt') -or ($request -match '1 file reputation and 0 certificate reputation were successfully set'))
        {       
            #Write-Host $request
            $message = (Get-Date -Format g) + " imported reputation: " + $myJson 
            Add-Content -Path $ErrLogpath -Value $message
            $message = (Get-Date -Format g) + " reqiest: " + $request
            Add-Content -Path $ErrLogpath -Value $message
        }
        else
        {
             $errorcode = -1
        }
    }
    else
    {
        Write-Host "Error: "$returncode

        $errorcode = -1
        #exit $errorcode
    }

    $errorcode
    return $errorcode
}

# convert hex to char-array decimal encoded
function global:Convert-HashToByteArray($hashvalue) {
    
    return $hashvalue -split '([A-F0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}
}

# define actions on event
$OnCreate = { 
  $text = "event: [{0}] in {1} : {2}" –f    $eventArgs.ChangeType, $eventArgs.FullPath, $Event.TimeGenerated 
  out_Text ($text) # log
  $EventsArrayList.Add($eventArgs)
}
$OnChange = {
  $text = "event: [{0}] in {1} : {2}" –f    $eventArgs.ChangeType, $eventArgs.FullPath, $Event.TimeGenerated
  out_Text ($text) # log
  $EventsArrayList.Add($eventArgs)
}

$OnRename = {
  $text = "event: [{0}] in {1} : {2}" –f    $eventArgs.ChangeType, $eventArgs.FullPath, $Event.TimeGenerated
  out_Text ($text) # log
  $EventsArrayList.Add($eventArgs)
}

$OnDelete = {
  $text = "event: [{0}] in {1} : {2}" –f    $eventArgs.ChangeType, $eventArgs.FullPath, $Event.TimeGenerated
  out_Text ($text) # log
  $EventsArrayList.Add($eventArgs)
}

# subscribes event for file CREATE, CHANGE, RENAME, DELETE
Register-ObjectEvent -InputObject $FSW -EventName Created -SourceIdentifier FileCreated -Action $OnCreate | Out-Null
Register-ObjectEvent -InputObject $FSW -EventName Changed -SourceIdentifier FileChanged -Action $OnChange | Out-Null
Register-ObjectEvent -InputObject $FSW -EventName Renamed -SourceIdentifier FileRenamed -Action $OnRename | Out-Null
Register-ObjectEvent -InputObject $FSW -EventName Deleted -SourceIdentifier FileDeleted -Action $OnDelete | Out-Null

# subscribed events are running in background and could be terminated with Unregister-Event -SourceIdentifier * see above
# or to stop the monitoring, run the following commands: 
# Unregister-Event FileDeleted 
# Unregister-Event FileCreated 
# Unregister-Event FileChanged
# Unregister-Event FileRenamed

$Timer = New-Object -Type System.Timers.Timer
$Timer.Interval = 2000 # 2 sec

$complete = 0
$action = {
#write-host "complete: $complete"
CheckFilterEventType
if($complete -eq 1)
   {
     $timer.stop()
     Unregister-Event thetimer
   }
}

Register-ObjectEvent -InputObject $timer -EventName elapsed –SourceIdentifier  thetimer -Action $action

$timer.start()

#Unregister-Event -SourceIdentifier *
#$Message = (Get-Date -Format g) + " Terminating Script."
#Add-Content -Path $ErrLogpath -Value $Message