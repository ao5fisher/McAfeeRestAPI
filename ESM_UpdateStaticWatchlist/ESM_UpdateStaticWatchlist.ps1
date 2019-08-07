
<#####################################################################################
 # File: SHU_ESM_UpdateStaticWatchlist.ps1
 # Description: Updates given static Watchlist on ESM with delta values from file comparison
 # Created by Andrei Oleinikow
 # Version 1.0
 # Copyright (c) Systemhaus-Ulm GmbH, 2018
 #####################################################################################>




# initialize variables
# set esm-server name
$EsmServer = 's-prod-esm01'
$esmhost = 'https://' + $EsmServer +'/rs/esm/'
$watchlistname = 'TestMe'

# paths to folder and files
$ErrLogPath = $PSScriptRoot + '\SHU_ESM_UpdateStaticWatchlist.log'
$PathToActualInputFile = "C:\test\compare\GroupsList-HERAKLES.csv"
$PathToPreviousInputFile = "C:\test\compare\previous\GroupsList-HERAKLES.csv"

#announce name-spaces
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web

# disable certificate checks
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


# add ssl protocols to avoid transfer errors
$AllProtocols = [System.Net.SecurityProtocolType] 'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# set error-level
$errorcode = 0


# create an log-file, if not exists. Use same folder as for script.
if (-not (Test-Path $ErrLogPath)) 
{
    New-Item -Path $ErrLogPath -ItemType file

}

# begin
$Message = (Get-Date -Format g) + " Starting logging."
Add-Content -Path $ErrLogpath -Value $Message

# check for $PathToActualInputFile 
try
{
    # resolve path
    $global:Path = Resolve-Path($PathToActualInputFile) -ErrorAction Stop
}
catch
{
    # write to error-log
    Write-Host "Path" $PathToActualInputFile "do not exists"

    $Message = (Get-Date -Format g) + " Path " + $PathToActualInputFile + " do not exists."
    Add-Content -Path $ErrLogPath -Value $Message

    $Message = (Get-Date -Format g) + " Terminating Script."
    Add-Content -Path $ErrLogpath -Value $Message
    # terminate on failure
    exit
}



# function out_Text() to log events
function global:out_Text($txt)
{ 
    Write-Host („{0}“ -f $txt) 
    Add-Content -Path $ErrLogpath -Value $txt
}


# this function send web-request to the esm server
function global:SendWebRequest($toadditems, $todeleteitems)
{
    $errorcode = 0
	Add-Content -Path $ErrLogpath -Value "sending web request."
    $url = "https://" + $EsmServer + "/rs/esm/login "
	
	# set credentials
	# send web-request, get session token
	$username = 'userxy'
	$passwd = 'Password'

	$v10_b64_user = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username))
	$v10_b64_passwd = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($passwd))

	$v10_params = @{
			username = $v10_b64_user
			password = $v10_b64_passwd
			locale = 'en_US'};        
	$body = $v10_params | ConvertTo-Json

	$headers = @{
		'Content-Type' = 'application/json'
		};

	$login_headers = $headers
	$login_headers.Add("Authorization", "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$passwd )))

	#login, get tocken
	$login_url = $esmhost + "login"
	$response = Invoke-WebRequest $login_url -Method Post -Headers $login_headers -Body $body -SessionVariable Cookie
    Write-Host $response.StatusCode
    $Message = (Get-Date -Format g) + " try to login, returncode: $response.StatusCode."
    Add-Content -Path $ErrLogpath -Value $Message
    if ($response.StatusCode -ne 201)
    {
        return $response.StatusCode
    }
	# add X-Xsrf-Token to http headers
	$headers.Add('X-Xsrf-Token', $response.headers.Get_Item('Xsrf-Token'))

    
    #hier get id of watchlist
    $method = 'sysGetWatchlists?hidden=false&dynamic=false&writeOnly=false&indexedOnly=false'
	$url = $esmhost + $method
	$response = Invoke-WebRequest $url -Method Post -ContentType "application/json" -Headers $headers -WebSession $Cookie
    #write-host "Hallo" $response.Content 
    $out = ConvertFrom-Json $([String]::new($response.Content))#$response.Content # | Out-String #| ConvertFrom-Json
    #$out.return

    foreach($item in $out.return)
    {
        $item.name
        if ($item.name -eq $watchlistname)
        {
            $myid = $item.id
        }

    }

    #hier to add items to watchlist
    if($toadditems -ne $null)
    {
        if($toadditems.count -eq 1)
        {
            $bodyaddparams = @{
	            watchlist = $myid
		        values = @($toadditems)};  
    
	        $bodyadd = $bodyaddparams | ConvertTo-Json
            Write-Host $bodyadd
        }else
        {
            $bodyaddparams = @{
	            watchlist = $myid
		        values = $toadditems};  
        

	        $bodyadd = $bodyaddparams | ConvertTo-Json
            #################
            Write-Host $bodyadd
            ###################
        }
        $method = 'sysAddWatchlistValues'
	    $url = $esmhost + $method
	    $response = Invoke-WebRequest $url -Method Post -ContentType "application/json" -Headers $headers -Body $bodyadd -WebSession $Cookie
        Write-Host "Added StatusCode: "$response.StatusCode
        $Message = (Get-Date -Format g) + " try to add, returncode: $response.StatusCode."
        Add-Content -Path $ErrLogpath -Value $Message
    }

    #hier to delete items from watchlist
    if($todeleteitems -ne $null)
    {
        if($todeleteitems.count -eq 1)
        {
            $bodydeleteparams = @{
	            watchlist = $myid
		        values = @($todeleteitems)};  
    
	        $bodydelete = $bodydeleteparams | ConvertTo-Json
            Write-Host $bodydelete
        }else
        {
            $bodydeleteparams = @{
	            watchlist = $myid
		        values = $todeleteitems};  
    
	        $bodydelete = $bodydeleteparams | ConvertTo-Json
            Write-Host $bodydelete
        }  
        $method = 'sysAddWatchlistValues'
	    $url = $esmhost + $method
	    $response = Invoke-WebRequest $url -Method Post -ContentType "application/json" -Headers $headers -Body $bodydelete -WebSession $Cookie
        Write-Host "Deleted StatusCode: "$response.StatusCode
        $Message = (Get-Date -Format g) + " try to add, returncode: $response.StatusCode."
        Add-Content -Path $ErrLogpath -Value $Message
    }
    #$output
	#logout
	$url = $esmhost + 'logout'
    Write-Host 'Logout'
	$responsex = Invoke-WebRequest $url -Method Delete -Headers $headers -WebSession $Cookie
    $Message = (Get-Date -Format g) + " try to logout, returncode: $responsex.StatusCode."
    Add-Content -Path $ErrLogpath -Value $Message
	$returncode = $responsex.StatusCode
    return $returncode
}

#compare actual and previous, write delta to watchlist
$delta = Compare-Object -ReferenceObject (Get-Content -Path $PathToActualInputFile) -DifferenceObject (Get-Content -Path $PathToPreviousInputFile)
$todelete = $delta | Where-Object {$_.SideIndicator -eq "=>"}
$toadd = $delta | Where-Object {$_.SideIndicator -eq "<="}

if($delta -ne $null)
{
    write-host "files are not equal"
    #write lowercase
    $toaddarray = $toadd.InputObject | %{[string[]]$_.ToLower()}

    $todeletearray = $todelete.InputObject | %{[string[]]$_.ToLower()}
    
    $Message = (Get-Date -Format g) + " to add are: $toaddarray."
    Add-Content -Path $ErrLogpath -Value $Message
    $Message = (Get-Date -Format g) + " to delete are: $todeletearray."
    Add-Content -Path $ErrLogpath -Value $Message
    $returncode = SendWebRequest -toadditems $toaddarray -todeleteitems $todeletearray
    Write-Host "Webrequest: "$returncode
    if ($returncode -eq 200)
    {
        #copy actual to previous
        Copy-Item -Path $PathToActualInputFile -Destination $PathToPreviousInputFile -Force
        $Message = (Get-Date -Format g) + " copying $PathToActualInputFile to $PathToPreviousInputFile."
        Add-Content -Path $ErrLogpath -Value $Message
    }
    else
    {
        $Message = (Get-Date -Format g) + " Webrequest failed, Error: $returncode."
        Add-Content -Path $ErrLogpath -Value $Message
    }
}
else
{
    write-host "files are equal"
    $Message = (Get-Date -Format g) + " nothing to add or delete, files are equal."
    Add-Content -Path $ErrLogpath -Value $Message
}


#exit
$Message = (Get-Date -Format g) + " exit, end logging."
Add-Content -Path $ErrLogpath -Value $Message
exit