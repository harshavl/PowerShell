##############################################################################
# HP OneView OVSync Library
##############################################################################
##############################################################################
## (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
##############################################################################
<#



#>

#Revision History
#------------------------------------------
<#
2.00.01.00
     |  - Initial release for HP OneView 2.0.  NOTE:  This library version does not support older appliance versions.
     |  - Support to replicate OneView managed template resources to multiple OneView target appliances
	 |  
     
#>

# Set OVSync Library Version
# format
# xx  - Major OneView Version
# .xx - Minor OneView version
# .xx - Version Major number
# .xx - Version Minor number
$script:scriptVersion = "2.00.01.00"

$script:LogFilePath = ".\logs\"
$script:dateFormat = get-date -format MMddyyyyHHmmss
$script:LogFile = $LogFilePath + "\" + "OVSync" + "." + $dateFormat + ".log"

# Dependency check - Module depends on HPOneView.200 library
#Check to see if another module is loaded in the console, but allow Import-Module to process normally if user specifies the same module name
if ($(get-module -name HPOneView*) -and (-not $(get-module -name HPOneView* | % { $_.name -eq "HPOneView.200"}))) { 

    write-Host "CRITICAL:  Another HP OneView module is already loaded:  "  -ForegroundColor Yellow -BackgroundColor Black 
    Write-Host "  |"  -ForegroundColor Yellow -BackgroundColor Black 
    get-module -name HPOneView* | % { write-host "  |--> $($_.name) ($($_.Version))"  -ForegroundColor Yellow -BackgroundColor Black }
    write-host ""

    [System.String]$Exception = 'InvalidOperationException'
    [System.String]$ErrorId = 'CannotLoadMultipleLibraries'
    [System.Object]$TargetObject = 'Import-Module HPOneView.120'
    [System.Management.Automation.ErrorCategory]$ErrorCategory = 'ResourceExists'
    [System.String]$Message = 'Another HP OneView module is already loaded.  The HP OneView PowerShell library does not support loading multiple versions of libraries within the same console.'
    
    $_exception = New-Object $Exception $Message
    $errorRecord = New-Object Management.Automation.ErrorRecord $_exception, $ErrorID, $ErrorCategory, $TargetObject
    throw $errorRecord
}
else
{
	# Module is not loaded - Explicit loading of Module
	Import-Module -DisableNameChecking .\HPOneView.200.psm1 -WarningAction "SilentlyContinue" -Verbose:$false

	$modCheck = Get-Module | ? {$_.name -match "HPOneView"}
	if(!$modCheck){
		Throw "HPOneView PowerShell module failed to load."; return
	}
}

# List of resource URI's to replicate
$script:uris = [Ordered]@{
	#"fwbundles.json" = "/rest/firmware-bundles";
	"network.json" = "/rest/ethernet-networks";	
	"fc_network.json" = "/rest/fc-networks";
	"fcoe_network.json" = "/rest/fcoe-networks";
	"networkset.json" = "/rest/network-sets";
	"lig.json" = "/rest/logical-interconnect-groups";
	"enclosureGroup.json" = "/rest/enclosure-groups";
	"serverprofile_template.json" = "/rest/server-profile-templates";
    "serverhardwaretypes.json" = "/rest/server-hardware-types"
}

$script:deleteUris = [Ordered]@{
    "serverprofile_template.json" = "/rest/server-profile-templates";
    "enclosureGroup.json" = "/rest/enclosure-groups";
    "lig.json" = "/rest/logical-interconnect-groups";
    "networkset.json" = "/rest/network-sets";
    "fcoe_network.json" = "/rest/fcoe-networks";
    "fc_network.json" = "/rest/fc-networks";
    "network.json" = "/rest/ethernet-networks"
}

$script:auditLogs = [Ordered]@{

    "serverhardwaretypes.json" = "/rest/audit-logs?filter=%22objectType%3D'server-hardware-types'%22";
    "serverprofile_template.json" = "/rest/audit-logs?filter=%22objectType%3D'server-profile-templates'%22";
   "enclosureGroup.json" = "/rest/audit-logs?count=200&start=0&filter=%22action%3D'modify'%22&filter=%22objectType%3D'enclosure-groups'%22";
    "lig.json" = "/rest/audit-logs?filter=%22objectType%3D'logical-interconnect-groups'%22";
    "networkset.json" = "/rest/audit-logs?filter=%22objectType%3D'network-sets'%22";
    "fcoe_network.json" = "/rest/audit-logs?filter=%22objectType%3D'fcoe-networks'%22";
    "fc_network.json" = "/rest/audit-logs?filter=%22objectType%3D'fc-networks'%22";
    "network.json" = "/rest/audit-logs?filter=%22objectType%3D'ethernet-networks'%22"
     }
$script:deleteAll = [Ordered]@{
     #"/rest/storage-systems";
      #"/rest/server-hardware";
       # "/rest/storage-volumes";
        #"/rest/storage-pools";
       #"/rest/storage-volume-templates";
       "/rest/server-profiles" = 30;
     "/rest/server-profile-templates" = $null;
      #"/rest/server-profiles" = 30;
         "/rest/enclosure-groups" = $null;
        #"/rest/enclosures" = 30;
        "/rest/logical-interconnect-groups" = $null;
        "/rest/network-sets/" = $null;
         "/rest/fcoe-networks" = $null;
         "/rest/fc-networks" = $null;
         "/rest/ethernet-networks" = $null
}

# Helper functions 

function writeLog {
	<#
        .SYNOPSIS
        Log informational messages 

        .DESCRIPTION
        This internal helper function will log messages to assist with debugging

        .PARAMETER Message DebugLevel
        [System.Object] Message data
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
	Param (
		[parameter (ValueFromPipeline = $true)]
		[System.Object]$message,
		[System.String]$debuglevel = "INFO"
	)
	Begin {
		# Test for existence of log directory
		if(! (Test-Path -Path $script:LogFilePath -PathType Container))
		{
			New-Item -ItemType Directory -Path $script:LogFilePath
		}
	}
	Process {
		$date = Get-Date -format MM:dd:yyyy-HH:mm:ss	
	
		if ($debuglevel -eq "INFO")
		{
			Write-Output "$date INFO: $message" | Out-File $script:LogFile -append
		}
		elseif ($debuglevel -eq "DEBUG")
		{
			Write-Output "$date DEBUG: $message" | Out-File $script:LogFile -append
		}
		elseif ($debuglevel -eq "WARNING")
		{
			Write-Output "$date WARNING: $message" | Out-File $script:LogFile -append
		}
		elseif ($debuglevel -eq "ERROR")
		{
			Write-Output "$date ERROR: $message" | Out-File $script:LogFile -append
		}
	}
}

### Additonal Helper functions starts.


function mergerHashTables($htold, $htnew)
{
    <#
        .SYNOPSIS
        Merge two hash table 

        .DESCRIPTION
        This internal helper function will merge the two hash table.

        .PARAMETER 
        [System.Collections.Hashtable] old hash table
	    [System.Collections.Hashtable] new hash table

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
	$keys = $htold.getenumerator() | foreach-object { $_.key }
	$keys | foreach-object {
		$key = $_
		if ($htnew.containskey($key))
		{
			$htold.remove($key)
		}
	}
	$htnew = $htold + $htnew
	return $htnew
}

function compareJson ( ) 
{
    <#
        .SYNOPSIS
        Compare two json file.

        .DESCRIPTION
        This internal helper function will compare the two json file.

        .PARAMETER 
        None

        .INPUTS
        /base.json
		/target.json

        .OUTPUTS
        /dest_diff.json       
    #>

    $content1 = Get-Content $Script:Temp\base.json
    $content2 = Get-Content $Script:Temp\target.json 

    $trimContent1 = $content1 -replace ",",""
    $trimContent2 = $content2 -replace ",",""

    $json_1 =  $trimContent1 -Replace '(^\s+|\s+$)','' -Replace '\s+',' ' | sort
    $json_2 = $trimContent2 -Replace '(^\s+|\s+$)','' -Replace '\s+',' ' | sort
          
    ## Set difference B - A
    [array]$out_2=$json_2 | ?{ -not ( $json_1 -contains $_ ) }
    ## Set difference A - B
    [array]$out_1=$json_1 | ?{ -not ( $json_2 -contains $_ ) }

    if ( $out_1 -eq $out_2 )
    {

        writeLog "Both $src_content.name and $dest_net.name json files are same "
        return "NO"

    }
    elseif ( $out_1.count -eq $out_2.count )
    {
        $lookup=@{}
        for ( $i = 0; $i -lt $out_2.count; $i++ )
        {
            $lookup.Add( $out_1[$i], $out_2[$i] )

        } 
       # mapParameter $lookup $out_1 $out_2

        foreach ( $swift in $lookup.GetEnumerator() )
        {
                 
            Replace  $($swift.Value) $($swift.Key) "$Script:Temp\dest_diff.json"
            writeLog " Difference between base and target attributes are:"
            WriteLog "$($swift.Value)"

        }

        return "YES"
     }
     else
     {

        #Copy-Item $Script:Dest\Temporary\base.json" ".\Temporary\dest_diff.json"
        

        Copy-Item $Script:DestinationFolder\Temp\base.json $Script:DestinationFolder\Temp\dest_diff.json
        WriteLog " Difference between base and target attributes are:"
        WriteLog "$content2"
        return "YES"

     }

 } # End of the Comparison

 function diffAttributes  ( [Object]$src_json,[Object]$src_uri,[System.Object]$dest_json,[System.String]$dest_uri, [System.String]$Component ) 
{

	isDirectory "$Script:Temp" "dir"
    isDirectory "$Script:Temp\dest_diff.json" "file"
    isDirectory "$Script:Temp\base.json" "file"
    isDirectory "$Script:Temp\target.json" "file"

	
	if($Component -eq "Networks")
	{
     
    $destjson = $dest_json | ConvertFrom-Json
	$dest_uri = $destjson.$dest_uri
    $desturi_field = Send-HPOVRequest -uri $dest_uri GET
       
    $desturi_field | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\dest_diff.json
    $temp = Get-Content $Script:Temp\dest_diff.json
    $removespace = $temp -Replace '(^\s+|\s+$)','' -Replace '\s+',' '  | Out-File -filepath $Script:Temp\dest_diff.json
   
	$put_uri = $desturi_field.uri

    $desturi_field | select * -ExcludeProperty description,eTag,created,uri,name,modified |ConvertTo-Json  | Out-File -filepath $Script:Temp\target.json
    $src_uri |  select * -ExcludeProperty description,eTag,created,uri,name,modified | ConvertTo-Json | Out-File -filepath $Script:Temp\base.json

	}
	elseif ( $Component -eq "LIG")
	{
        $dest_json | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\dest_diff.json
        $temp = Get-Content $Script:Temp\dest_diff.json
        $removespace = $temp -Replace '(^\s+|\s+$)','' -Replace '\s+',' '  | Out-File -filepath $Script:Temp\dest_diff.json
        
		$dest_json | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9  | Out-File -filepath $Script:Temp\target.json   
		$src_json | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9 | Out-File -filepath $Script:Temp\base.json
		$put_uri = $dest_json.uri
	}
    elseif ( $Component -eq "netLink" )
    {
        $dest_json | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\dest_diff.json
        $temp = Get-Content $Script:Temp\dest_diff.json
        $removespace = $temp -Replace '(^\s+|\s+$)','' -Replace '\s+',' '  | Out-File -filepath $Script:Temp\dest_diff.json
        
        $dest_json | select * -ExcludeProperty uri,connectionTemplateUri |ConvertTo-Json -Depth 9  | Out-File -filepath $Script:Temp\target.json   
        $src_json | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9 | Out-File -filepath $Script:Temp\base.json
        $put_uri = $dest_json.uri 

    }
    elseif ( $Component -eq "NetworkSet")
    {
        $destjson = $dest_json | ConvertFrom-Json
        $put_uri = $destjson.uri

        $targetConnTemplate = $destjson.connectionTemplateUri
        $baseConnTemplate = $src_json.connectionTemplateUri
        

        $baseJson = $src_json  | select * -ExcludeProperty uri

        $destjson | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\dest_diff.json
        $temp = Get-Content $Script:Temp\dest_diff.json
        $removespace = $temp -Replace '(^\s+|\s+$)','' -Replace '\s+',' '  | Out-File -filepath $Script:Temp\dest_diff.json
        
        $destjson | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9  | Out-File -filepath $Script:Temp\target.json 
        $baseJson | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9 | Out-File -filepath $Script:Temp\base.json
        Replace $baseConnTemplate $targetConnTemplate $Script:Temp\base.json
                        
    }
    elseif ( $Component -eq "SPT" )
    {
        $dest_json | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\dest_diff.json
        $temp = Get-Content $Script:Temp\dest_diff.json
        $removespace = $temp -Replace '(^\s+|\s+$)','' -Replace '\s+',' '  | Out-File -filepath $Script:Temp\dest_diff.json

        $dest_json | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9  | Out-File -filepath $Script:Temp\target.json   
		$src_json | select * -ExcludeProperty uri |ConvertTo-Json -Depth 9 | Out-File -filepath $Script:Temp\base.json
		$put_uri = $dest_json.uri

    }

    $result = compareJson
                
    if ($result -eq "YES" )
    {
        $post = Get-Content $Script:Temp\dest_diff.json -Raw | convertFrom-json | select * -ExcludeProperty description,eTag,created,uri,modified
                
         postTarget $post "PUT" $put_uri   
     }

 
} ## ENd of the compare

function Get_PreviousName ( $uri , $auditLog )
{ # Get Previous Name from the audit Log

    <#
        .SYNOPSIS
        Make difference between base and target components.

        .DESCRIPTION
        This internal helper function is if the difference between base and target components and then replace in the target components.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>

   $flag = 0
   [array]::Reverse($auditLog)

    foreach ( $audit in $auditLog )
    {
        if ( $flag -eq 1 -and $uri -eq $audit.objectTypeDescriptor )
        {
            if ( $audit.msg -match "'")
            {
                 return $audit.msg.Split("'")[1]
            }
            elseif ( $audit.msg -match '"')
            {
                return $audit.msg.Split('"')[1]

            }
            else
            {
                $temp =$audit.msg.Split(':')[1]
                $result = $temp -replace "\."," " 
                return $result
            
            }
                
        }

        if ( $uri -eq $audit.objectTypeDescriptor )
        {
               $flag = 1
        }
    } 

}  

function postTarget ($post, $decide, $uri,$node)
{	
    	<#
        .SYNOPSIS
        POST/PUT/DELETE the json files.

        .DESCRIPTION
        This internal helper function is post/put/delete the json file sequentially.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>

    if ( $decide -eq "DELETE" )
    {
         try 
        {
           writeLog "JSON DELETE requested for $uri "
           #$json | ConvertTo-Json -Depth 99 | writeLog
           $task = Send-HPOVRequest -uri $uri $decide  -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
           $task | ConvertTo-Json -Depth 99 | writeLog
           #Wait for task to complete
           $taskStatus = Wait-HPOVTaskComplete $task.uri -timeout (New-Timespan -minutes 2)                
           $taskStatus | ConvertTo-Json -Depth 99 | writeLog
           writeLog "JSON DELETE complete"
        }
        catch
        {
            writeLog "Resource NOT exists"
            writeLog "$_.Exception" -debuglevel "ERROR"
        }


    }

	foreach ($json in $post)
	{

    if ( $decide -eq "PUT" )
    {
        try 
        {
           writeLog "JSON PUT requested for $uri "
           $json | ConvertTo-Json -Depth 99 | writeLog
           $task = Send-HPOVRequest -uri $uri $decide $json -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
           $task | ConvertTo-Json -Depth 99 | writeLog
           #Wait for task to complete
           $taskStatus = Wait-HPOVTaskComplete $task.uri -timeout (New-Timespan -minutes 2)                
           $taskStatus | ConvertTo-Json -Depth 99 | writeLog
           writeLog "JSON PUT complete"
        }
        catch
        {
            writeLog "Resource exists"
            writeLog "$_.Exception" -debuglevel "ERROR"
        }
    }
   
    else
    { 
        try
        {
            writeLog "JSON POST requested for $($path.Value)"
        
            $json | ConvertTo-Json -Depth 99 | writeLog
            if($node -eq "SHT")
            {
		        $task = Send-HPOVRequest -uri $uri POST $json -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            else{
                $task = Send-HPOVRequest -uri $($path.Value) POST $json -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            $task | ConvertTo-Json -Depth 99 | writeLog

            #Wait for task to complete
            $taskStatus = Wait-HPOVTaskComplete $task.uri -timeout (New-Timespan -minutes 2)                
            $taskStatus | ConvertTo-Json -Depth 99 | writeLog
        
            writeLog "JSON POST complete"
        }
        catch
        {
            writeLog "Resource exists"
            writeLog "$_.Exception" -debuglevel "ERROR"
        }
	}
   } ## End of loop
}

function connectFusion([string]$ipAddress, [string]$appUname, [string]$appPwd)
{
    	<#
        .SYNOPSIS
        Connect to HPOV Appliance.

        .DESCRIPTION
        This internal helper function Connect to HPOV Appliance.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>
	writeLog " FUNCTION BEGIN Connect-Fusion"
	Write-Host "." -NoNewline
    $script:returnCode = Connect-HPOVMgmt -appliance $ipAddress -user $appUname -password $appPwd
    writeLog " FUNCTION END Connect-Fusion"  
    return $script:returnCode
}

function DisconnectFusion ()
{    
    <#
        .SYNOPSIS
        Disconnect to HPOV Appliance.

        .DESCRIPTION
        This internal helper function Disconnect to HPOV Appliance.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>
    $script:returnCode = Disconnect-HPOVMgmt
    return $script:returnCode 
}

function Replace ([System.String]$source,[System.String] $dest, [System.String]$file)
{
    <#
        .SYNOPSIS
        Replace strings in the json files.

        .DESCRIPTION
        This internal helper function Replace strings in the json files.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>
	(get-content $file).replace($source, $dest) | set-content $file
}

function getValueFromJson ( $Search, $JsonFile )
{ 
    	<#
        .SYNOPSIS
        Get the Value with respect to key from the json file.

        .DESCRIPTION
        This internal helper function Get the Value with respect to key from the json file.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>

    foreach ( $file in $JsonFile )
    {
        if ( $file.name -eq $Search )
        {
              return $file.uri
        }
     }
 }


function isDirectory ( [System.String] $dir, [System.String]$code ) 
{
    	<#
        .SYNOPSIS
        Check the directory/file exists.

        .DESCRIPTION
        This internal helper function Check the directory/file exists.

        .PARAMETER 
        None

        .INPUTS
        None

        .OUTPUTS
        None       
    #>
    if ( $code -eq "file" ) 
    {
       if (!(Test-Path -Path $dir ))
	    {
		    $doNotDisplay = New-Item -ItemType file -Path $dir
	    }
     
    }
    else
    {

        if (!(Test-Path -Path $dir ))
	    {
		    $doNotDisplay = New-Item -ItemType directory -Path $dir
	    } 
    }
 }


function mapParameter ( [Array]$name, [Array]$value )
{
    
    $hash_name=@{}
    
    for ($lookup = 0; $lookup -lt $name.count; $lookup++)
	{
				$hash_name.Add($name[$lookup], $value[$lookup])
	}
    return $hash_name

}
function Create_ElementNamesJson ( $HashName, $FolderName )
{
    
	<#
        .SYNOPSIS
        GET the json files from the target appliance.

        .DESCRIPTION
        This internal helper function GET the json files from the target appliance.

        .PARAMETER 
        [System.Object] HashName
		[System.String] FolderName
		
        .INPUTS
        None

        .OUTPUTS
        None       
    #>
	foreach ($fh in $HashName.GetEnumerator() )
    {
	    $NameURI = Send-HPOVRequest -uri $($fh.Value) GET
        $file = $($fh.Key) -Replace '\s',''
        $NameURI | ConvertTo-Json -depth 99 | Out-File -filepath $Script:BaseFolder/$FolderName/$file.json
    }
}

function validateConnection ( $returnCode )
{
    
	<#
        .SYNOPSIS
        Validate the appliance connection.

        .DESCRIPTION
        This internal helper function Validate the appliance connection.

        .PARAMETER 
        None
		
        .INPUTS
        None

        .OUTPUTS
        None       
    #>
    if($returnCode)
    {      
        WriteLog "101"
	    Write-Host
	    Write-Host "ERROR: Incorrect username or password supplied to $ApplianceIP " -ForegroundColor Yellow -BackgroundColor Black 
	    writeLog "ERROR: Incorrect username or password supplied to $ApplianceIP "
    }
}

function Create_PreviousElement_URI ( $baseDiff, $baseJson, $targetJson, $auditFile )
{
    	<#
        .SYNOPSIS
        Find the previous element name from the Audit Logs.

        .DESCRIPTION
        This internal helper function Find the previous element name from the Audit Logs.

        .PARAMETER 
        [System.String] Base Element Names.
		[System.Object] Base Json file.
		[System.Object] Target Json file.
		[System.Object] Audit Log
		
        .INPUTS
        None

        .OUTPUTS
        Previous Element name and URI       
    #>
    $auditUri = @{}
    foreach ( $Base in $baseDiff )
    {
        $json = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $json.MaxJsonLength = 2000000000 # 2 GB
               
      <#  $auditJson = Get-Content $Script:ReferenceFolder\Audit\network.json 
        $auditData = $json.Deserialize($auditJson, [System.Object])
        $auditLog = $auditData.members.value 
      #>

        $auditRaw = Get-Content "$Script:ReferenceFolder\Audit\$auditFile" -Raw | ConvertFrom-Json

      <#  if($auditFile -eq "serverprofile_template.json")
        {
            $auditJson = $auditRaw.members | ConvertTo-Json
        }else{
            $auditJson = $auditRaw.members.value | ConvertTo-Json
        }
        #>

        
        if ( $auditRaw.members.count )
        {

	        $auditJson = $auditRaw.members | ConvertTo-Json

        }
        else {
	        $auditJson = $auditRaw.members.value | ConvertTo-Json
        }

        $auditLog = $json.Deserialize($auditJson, [System.Object])

        $baseUri = getValueFromJson $Base $baseJson 
        $URICount = ([regex]::Matches($auditJson, $baseUri )).count

        if ( $URICount -gt 1 )
        {
            $previousElementname = Get_PreviousName $baseUri $auditLog
            writeLog "At Target Appliance changing the Name $previousElementname. "
            $auditUri += mapParameter $baseUri $previousElementname 
        }              
    }

    return $auditUri

 }

function Get_Json_ByName ( $KeyName, $JsonFile )
{
    	<#
        .SYNOPSIS
        Find the Json file with respect to Name.

        .DESCRIPTION
        This internal helper function Find the Json file with respect to Name.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        Json file.     
    #>
    foreach ( $file in $JsonFile )
    {
        if ( $file.name -eq $KeyName )
        {
            return $file
        }
     }
 }

function changeTarget ( $baseDiff, $tarDiff, $srcJson, $tarJson , $pastNameTable ) 
{ 
    
	<#
        .SYNOPSIS
        Replace/Change the element names in the target appliance.

        .DESCRIPTION
        This internal helper function Replace/Change the element names in the target appliance.when the changes in the Base appliance.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
             
    #>
    foreach ( $json in $srcJson )
    {
        if ( $baseDiff.Contains( $json.name ) )
        {
            #Get the changed Network Name from the Target applaince 
            $baseName = getHashValue $json.uri $pastNameTable
            $baseNameTrim = $baseName -replace "\'",'' 
            if ( $baseName )
            {
                $targetJson = Get_Json_ByName $baseNameTrim.Trim("") $tarJson
                $baseJson = Get_Json_ByName $json.name $srcJson

                $baseJson | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\base.json
                $targetJson | ConvertTo-Json -depth 9  | Out-File -filepath $Script:Temp\target.json

                $swap = @{}
                if($targetJson)
                {
                    $swapUri = mapParameter $baseJson.uri $targetJson.uri
                    $swapTemplate = mapParameter $baseJson.connectionTemplateUri $targetJson.connectionTemplateUri
                    $swap = mergerHashTables $swapUri $swapTemplate
                }
                

                foreach ( $uri in $swap.GetEnumerator() )
                {

                    replace $($uri.Key) $($uri.Value) "$Script:Temp\base.json"

                }

                writeLog "Before Change json file "
                writeLog "$targetJson"
                writeLog "After Change json file"
                
                $putFile = Get-Content "$Script:Temp\base.json" -Raw | convertFrom-json
                writeLog "$putFile"

                $putUri = $putFile.uri
                postTarget $putFile "PUT" $putUri
            }
        }
    }
}

function getHashValue ( $Key_In, $Hash )
{
    foreach ( $var in $Hash.GetEnumerator() )
	{
		if ( $($var.Key) -eq $key_in )
		{
			return $($var.Value)
		}
	}
}

function fcNetworkReplicate ([Object]$jsonFile )
{
    <#
        .SYNOPSIS
        Replicate FC-Networks.

        .DESCRIPTION
        This internal helper function Replicate FC-Networks.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    Write-Host "Cloning FC Networks in progress .... " -NoNewline
    $targetFcJson = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    $targetFcId = @{}
    $targetFcId = mapParameter $targetFcJson.members.name $targetFcJson.members.uri 
    $tarFcJson = $targetFcJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description
    $srcFcDiffJson = $jsonFile.members | select * -ExcludeProperty  eTag, Created,status, modified, description

    [Array]$baseFc = $jsonFile.members.name
    [Array]$targetFc = $tarFcJson.name
    [Array]$targetDiff = $targetFc | ?{-not ($baseFc -contains $_)}
    [Array]$baseDiff = $baseFc | ?{-not ( $targetFc -contains $_)}

    if ( $baseDiff -and $targetDiff ) 
    {
        $pasrFcNetworkUri = @{}
        $pasrFcNetworkUri = Create_PreviousElement_URI $baseDiff $srcFcDiffJson $tarFcJson "fc_network.json"
        changeTarget  $baseDiff $targetDiff $srcFcDiffJson $tarFcJson $pasrFcNetworkUri
    }

    foreach ( $fc in $jsonFile.members)
    {
        $active = Get-HPOVNetwork $fc.name
        if( $active.state -eq "Active" )
        {
            $fcName=$fc.name -Replace '\s',''
            $fcUri = Get-Content $Script:ReferenceFolder\FC_Network\$fcName.json -Raw | convertFrom-json
            [String]$uri = $active.uri
        
            $destFc = Send-HPOVRequest -uri $uri GET
            $destFcJson = $destFc | ConvertTo-Json

            diffAttributes $fc $fcUri $destFcJson "connectionTemplateUri" "Networks"
        }
        else
        {
            $post = $fc | select * -ExcludeProperty  eTag, Created, *uri*, status, modified, description, connectionTemplateUri
            postTarget $post
        }
    } 
    Write-Host "`t`t`t`t Complete!"
}			

function networkReplicate ( [Object]$jsonFile )
{
    <#
        .SYNOPSIS
        Ethernet-Networks FC-Networks.

        .DESCRIPTION
        This internal helper function Replicate Ethernet-Networks.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>	

    $srcNet = $jsonFile.members | select * -ExcludeProperty  eTag, Created, *uri*, status, modified, description, connectionTemplateUri
    $srcDiffJson = $jsonFile.members | select * -ExcludeProperty  eTag, Created, status, modified, description
    $targetJson = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    $targetNetId = @{}
      
    [Array]$baseShift = $jsonFile.members.name
    [Array]$targetShift = $targetJson.members.name
    [Array]$targetDiff = $targetShift | ?{-not ($baseShift -contains $_)}
    [Array]$baseDiff = $baseShift | ?{-not ( $targetShift -contains $_)}
	 
    $targetJsonFilter = $targetJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description

    #
    # Make changes in the target appliance.When changes in the Base appliance
    #
    if ( $baseDiff -and $targetDiff )
    {
	    $pastElementUri = @{}
	    $pastElementUri =  Create_PreviousElement_URI $baseDiff $srcDiffJson $targetJsonFilter "network.json"
	    changeTarget  $baseDiff $targetDiff $srcDiffJson $targetJsonFilter $pastElementUri
    } 
            			
    if ($jsonFile.members.count -eq 0)
    {
	    writeLog " Ethernet Networks are empty in the base appliance "				
    }
    else
    {
	    Write-Host "Cloning Ethernet Networks in progress .... " -NoNewline
	    $targetNetworks = 	Get-Content $Script:DestinationFolder\network.json -Raw | convertFrom-json
	    foreach ( $net in $srcNet ) 
	    {
		    $active = Get-HPOVNetwork $net.name 
		    #
		    # When the Networks name are Present
		    #
		    if ( $active.state -eq "Active" )
		    {
                $uriName=$net.name -Replace '\s',''
                $srcUri = Get-Content $Script:ReferenceFolder\Network\$uriName.json -Raw | convertFrom-json
                $destJson = Send-HPOVRequest -uri $active.uri GET | ConvertTo-Json

                diffAttributes $net $srcUri $destJson "connectionTemplateUri" "Networks"

                $destJson = Send-HPOVRequest -uri $active.uri GET
                $destJsonFilter = $destJson | select * -ExcludeProperty  eTag, Created, status, modified, description,fabricUri
                diffAttributes $net $null $destJsonFilter $null "netLink"

		    }
		    else
		    {
			    $post = $net | select * -ExcludeProperty  eTag, Created, *uri*, status, modified, description, connectionTemplateUri
			    postTarget $post 
                 
            }                   
	    }	
        Write-Host "`t`t`t Complete!"		
    }	
}	

function findNamesInauditLog ( [String]$name,[String]$logFile )
{
    
	<#
        .SYNOPSIS
        Find the Previous name from the Audit-Logs.

        .DESCRIPTION
        This internal helper function Find the Previous name from the Audit-Logs.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
	$json = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
	$json.MaxJsonLength = 2000000000 # 2 GB
	$AuditJson = Get-Content "$Script:ReferenceFolder\Audit\$logFile"
    $auditData = $json.Deserialize($AuditJson, [System.Object])
	$auditLog = $auditData.members
	[array]::Reverse($auditLog)

    foreach ( $audit in $auditLog )
    {
        if ( $audit.msg -match $name )
        {
           if(  $audit.msg -match "Deleted" -or $audit -match "Delete" )
           {
                return "YES"
           }
           else
           {
                return "NO"
           }
        }

    }
 }

 function enclosureGroupReplicate ()
{
    	<#
        .SYNOPSIS
       Replicate the Enclosure Group.

        .DESCRIPTION
        This internal helper function Replicate the Enclosure Group.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    Write-Host "Cloning Enclosure group in progress ...." -NoNewline
            
    replaceLigUri
        		
	$egJson = Get-Content $Script:ReferenceFolder\enclosureGroup.json -Raw | convertFrom-json
    $egBaseJson = $egJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description
    $egTarJson = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    $egTargetJson = $egTarJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description

    [Array]$baseEG = $egBaseJson.name
    [Array]$targetEG = $egTargetJson.name

    [Array]$targetEGDiff = $targetEG | ?{ -not ($baseEG -contains $_ ) }
    [Array]$baseEGDiff = $baseEG | ?{ -not ($targetEG -contains $_ ) }

    if($baseEGDiff -and $targetEGDiff)
    {
        $pastElementUri = @{}
        #$pastElementUri =  Create_PreviousElement_URI $baseEGDiff $egBaseJson $egTargetJson "enclosureGroup"
       # changeTarget $baseEGDiff $targetEGDiff $egBaseJson $egTargetJson $pastElementUri
    }
    if ( $egBaseJson.Count -eq 0 )
    {
        writeLog "Enclosure Group are empty in the base appliance "	
        
    }
    else
    {
        foreach ( $eg in $egBaseJson )
        {
            $active = Get-HPOVEnclosureGroup $eg.name
            if ( $active.state -eq "Active" -or $active.state -eq "Normal" )
            {
                writeLog " EG Active "

            }
            else
            {
                $post = $eg | select * -ExcludeProperty  eTag, Created, uri, status, modified, description
	            postTarget $post

            }
         }

    }

    Write-Host "`t`t`t Complete!"	
	Start-Sleep -s 10
}

function replaceLigUri ()
{
    <#
        .SYNOPSIS
		Replicate the LIG name with target appliance URI.

        .DESCRIPTION
        This internal helper function Replicate the LIG name with target appliance URI.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    $lig_dest = Send-HPOVRequest -uri "/rest/logical-interconnect-groups" GET
			
	$eg_json = Get-Content $Script:ReferenceFolder\enclosureGroup.json -Raw | convertFrom-json
			
	$ligUri = @{}
               
    $ligUri = mapParameter $lig_dest.members.name $lig_dest.members.uri
            
			
	foreach ($uri in $eg_json.members.interconnectBayMappings.logicalInterconnectGroupUri | Get-Unique)
	{				
		if ($uri)
		{					
			foreach ($lig in $ligUri.GetEnumerator())
			{
				if ($uri -eq $($lig.Key))
				{
					Replace $uri $($lig.Value) "$Script:ReferenceFolder\enclosureGroup.json"
				}						
			}
		}
	}

}

function deleteHPOV ( $uri, $waitfor )
{
	<#
        .SYNOPSIS
		Deleting the components from the HP-OV.

        .DESCRIPTION
        This internal helper function Deleting the components from the HP-OV sequentially. 

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    $retVal = Send-HPOVRequest -uri $uri

    for ($i = 0; $i -lt $retVal.members.count; $i++)
    {
        $task = Remove-HPOVResource -nameOruri $retVal.members[$i].uri -force
        if ($task.uri -ne $null)
        {
            $taskList += [System.Array]$task.uri
        }
    }
   
    if ($taskList.Count -ge 1)
    {
        Wait-ForListOfTasksToComplete([int]$waitfor)
    }
}

function Wait-ForListOfTasksToComplete([int]$newTimeout)
{
	#Write-Log " FUNCTION BEGIN Wait-ForListOfTasksToComplete"
		
	$stopWatch = [diagnostics.stopwatch]::StartNew()
	$counter = 0
	#30 mins for server profile creationg for 10 server profile in each enclosure + updating iLO. usually each server profile deployment takes between 25-30 mins
	#10-20 mins for importing enclosure
	#90 mins for 8 switches. so around 12 mins per switch
	$waitTimeout = New-TimeSpan -Minutes $newTimeout
	#parallel testing
	$prevUri = ""
	$arUriList = @{ }
	
	$k = 0
	while (1)
	{
		for ($i = 0; $i -lt $taskList.count; $i++)
		{	
			#check all tasks status is completed
			if ($taskList.count -eq $counter)
			{
				#wait for extra time for browser to refresh on second or 3rd enclosure
				sleep -Seconds 45
				#Write-Log "All tasks are completed, Please check the detailed status in the UI"
                $taskList = @()
				return
			}
			
            <#
            if ($taskList.count -eq $errCnt){
                Write-Log "All tasks are completed with Error, please the details in the UI"
                return
            }
            #>
			
			sleep -Milliseconds 1000
			$taskUri = $taskList[$i]
			
			$taskRetObject = Send-HPOVRequest $taskUri
			
			#$arUri = $taskRetObject.associatedResourceUri
			$arUri = $taskRetObject.associatedResource.resourceUri
			
			#for the first time
			#if ($k -eq 0 ){
			#    $arUriList += $arUri
			#}
			
			if ($arUri -ne $null)
			{
				
				if ($prevUri -ne $arUri)
				{
					if ($taskRetObject.taskState -eq "Completed" -or $taskRetObject.taskState -eq "Warning" -or $taskRetObject.taskState -eq "Error")
					{
						#Write-Log "Task : $taskRetObject.name  status is: $taskRetObject.taskStatus"
						#$arUriList += $arUri
						if ($counter -eq 0)
						{
							$arUriList.Add($arUri, "Completed")
							$prevUri = $arUri
							$counter += 1
						}
						if (!$arUriList[$arUri])
						{
							$prevUri = $arUri
							$counter += 1
							$arUriList.Add($arUri, "Completed")
						}
						
					}
				}
			}
			
            <#
            if ($taskRetObject.taskState -eq "Error"){
                
                Write-Log "Task : $taskRetObject.name has Errors. Please check details in the UI"
                $errCnt += 1
            } 
            #>
			
			if ($taskRetObject.taskState -eq "Warning" -and $taskRetObject.taskStatus -eq "Switches are already Activated with given spp")
			{
				
				#Write-Log "task status: $taskRetObject.taskStatus" -debuglevel "WARN"
				$switchCnt += 1
			}
			
			if ($switchCnt -eq $taskList.count)
			{
				#Write-Log "Warning: $taskRetObject.taskStatus" -debuglevel "WARN"
				return
				
			}
		}
		#reset the for loop
		$i = 0
		$k += 1
		$message = "Counter Value: $counter Actual:"+ $taskList.Count +"Timer is:"+ $stopWatch.Elapsed.Minutes +"Minutes"+ $stopWatch.Elapsed.Seconds +"Seconds"
      #  Write-Log $message
		#exit if times out
		if ($stopWatch.Elapsed -gt $waitTimeout)
		{
			#Write-Log "Time-out in Wait-ForListOfTasksToComplete function"
			#Write-Log "Check the detailed status in the UI"
            $taskList = @()
			return
		}
	}
	#Write-Log "FUNCTION END Wait-ForListOfTasksToComplete"
}


function removeTargetComponents()
{
	<#
        .SYNOPSIS
		Deleting target components.When deleting in the base appliance.

        .DESCRIPTION
        This internal helper function Deleting target components.When deleting in the base appliance. 

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
	foreach ( $rem in $deleteUris.GetEnumerator())
	{
		$targetJson = Send-HPOVRequest -uri $($rem.Value) GET
		$baseJson = Get-Content $Script:ReferenceFolder\$($rem.key) -Raw | ConvertFrom-Json
	
		[Array]$baseNames = $baseJson.members.name
		[Array]$targetNames = $targetJson.members.name
		[Array]$baseDiff = $baseNames | ?{-not ( $targetNames -contains $_)}
		[Array]$targetDiff = $targetNames | ?{ -not ($baseNames -contains $_)}
	
		if( $targetDiff)
		{
			foreach( $name in $targetDiff)
			{
				$isRemove = findNamesInauditLog $name $($rem.Name) 
				if ( $isRemove -eq "YES")
				{
					$uri = getValueFromJson $name $targetJson.members
				    postTarget "null" "DELETE" $uri
				}
			}
		}
	}
}




function fcoeReplicate ( [Object]$jsonfile)
{
	<#
        .SYNOPSIS
		Replicate FCOE-Networks.

        .DESCRIPTION
        This internal helper function Replicate FCOE-Networks.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>

        $srcFcoeDiffJson = $jsonfile.members | select * -ExcludeProperty  eTag, Created, status, modified, description,fabricUri

		$targetFcoeJson = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json

        $targetFcoeId = @{}
        $targetFcoeId = mapParameter $targetFcoeJson.members.name $targetFcoeJson.members.uri 

        $targetFcoeJson = $targetFcoeJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description

        [Array]$baseFcoe = $jsonfile.members.name
        [Array]$targetFcoe = $targetFcoeJson.name
        [Array]$targetDiffFcoe = $targetFcoe | ?{-not ($baseFcoe -contains $_)}
        [Array]$baseDiffFcoe = $baseFcoe | ?{-not ($targetFcoe -contains $_)}

        if ( $baseDiffFcoe -and $targetDiffFcoe )
        {
                $pastFcoeNetworkUri = @{}
                $pastFcoeNetworkUri = Create_PreviousElement_URI $baseDiffFcoe $srcFcoeDiffJson $targetFcoeJson "fcoe_network.json"
                changeTarget  $baseDiffFcoe $targetDiffFcoe $srcFcoeDiffJson $targetFcoeJson $pastFcoeNetworkUri
        }


		if ($jsonfile.members.count -eq 0)
		{
			writeLog " FCOE Networks are empty in the base appliance "				
		}
		else
		{
            Write-Host "Cloning FCOE Networks in progress .... " -NoNewline
            $targetFcoe = Get-Content $Script:DestinationFolder\fcoe_network.json -Raw | convertFrom-json

            foreach ( $fcoe in $srcFcoeDiffJson )
            {
                $Active = Get-HPOVNetwork $fcoe.name 
                if ( $Active.state -eq "Active" )
                {
                    $uriName=$fcoe.name -Replace '\s',''
                    $baseUri = Get-Content $Script:ReferenceFolder\FCoE_Network\$uriName.json -Raw | convertFrom-json
                    $targetJson = Send-HPOVRequest -uri $Active.uri GET | ConvertTo-Json
                    diffAttributes $fcoe $baseUri $targetJson "connectionTemplateUri" "Networks"

                }
                else
                {
                    $post = $fcoe | select * -ExcludeProperty  eTag, Created,*uri*,status,modified,description,connectionTemplateUri,fabricuri
                    postTarget $post

                }
            }
		    Write-Host "`t`t`t`t Complete!"
		}		
}

function replaceNameToUri ()
{
	

	<#
        .SYNOPSIS
		Replace Ethernet-network name to target Ethernet-network URI.

        .DESCRIPTION
        This internal helper function Replace Ethernet-network name to target Ethernet-network URI.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>	
    $netTarget = Send-HPOVRequest -uri "/rest/ethernet-networks" GET
    $nameUri = @{ }	
    $nameUri = mapParameter $netTarget.members.name $netTarget.members.uri
    $netSetJson = Get-Content $Script:ReferenceFolder\networkset.json -Raw | convertFrom-json
			
    if ($netSetJson.members.count -gt 0)
    {
	    foreach ($value in $netSetJson.members.networkUris)
	    {					
		    foreach ($search in $nameUri.GetEnumerator())
		    {						
			    if ($value -eq $($search.Key))
			    {
				    Replace $value $($search.Value) "$Script:ReferenceFolder/networkset.json"
                    break
			    }
		    }
	    }
     }			
}

function replaceTargetHardwareUri ( [Object]$ligFile )
{
	<#
        .SYNOPSIS
		Replace hard-ware name to target hard-ware URI.

        .DESCRIPTION
        Replace hard-ware name to target hard-ware URI.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    $icJson = Send-HPOVRequest -uri "/rest/interconnect-types" GET			
	$fc_json = Send-HPOVRequest -uri "/rest/fc-networks" GET
    $net_dest = Send-HPOVRequest -uri "/rest/ethernet-networks" GET
    $nameUri = @{ }			
	$fcUri = @{ }
    $nameUri = mapParameter $net_dest.members.name $net_dest.members.uri
    $fcUri = mapParameter $fc_json.members.name $fc_json.members.uri
	$deviceUri = @{ }
	$deviceUri = mapParameter $icJson.members.name $icJson.members.uri
			
	### Replace  Network name to uri
			
	$ligFile = Get-Content $Script:ReferenceFolder\lig.json -Raw | convertFrom-json
    $ethFC = mergerHashTables $nameUri $fcUri

    if( $ligFile.members.internalNetworkUris.count)
    {
   	    foreach ($value in $ligFile.members.internalNetworkUris )
	    {
		    foreach($search in $ethFC.GetEnumerator() )
		    {
                $name = $value.Substring(0,$value.Length-3)
			    if($name -eq $($search.Key) )
			    {
				    $baseName = $name+"lig"
				    Replace $baseName $($search.Value) "$Script:ReferenceFolder\lig.json"
                    break	
			    }
		    }
	    }
    }
			
    foreach ($value in $ligFile.members.uplinkSets.networkUris )
	{
        $name = $value.Substring(0,$value.Length-3)
		foreach ($search in $nameUri.GetEnumerator())
		{					
			if ($name -eq $($search.Key))
			{						
				writeLog "$name $($search.Value) "
                $src_string = $name+"lig"						
				Replace $src_string $($search.Value) "$Script:ReferenceFolder\lig.json"	
                break					
			}
		}
		foreach ($fc in $fcUri.GetEnumerator())
		{					
			if ($name -eq $($fc.Key))
			{				
                $src_fc = $name+"lig"		
				Replace $src_fc $($fc.Value) "$Script:ReferenceFolder\lig.json"	
                break					
			}
		}				
	} #### End of Replace LIG
			
		$permUri = $ligFile.members.interconnectMapTemplate.interconnectMapEntryTemplates.permittedInterconnectTypeUri
			
		foreach ($value in $permUri)
		{				
			foreach ($search in $deviceUri.GetEnumerator())
			{					
				if ($value -eq $($search.Key))
				{						
					writeLog "$value $($search.Value) "
						
					Replace $value $($search.Value) "$Script:ReferenceFolder\lig.json"	
                   # break					
				}
			}
		}
}			

function ligReplicate ( [Object]$jsonfile) 
{     
	<#
        .SYNOPSIS
		Replicate LIG.

        .DESCRIPTION
        Replicate LIG.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    Write-Host "Cloning Logical Interconnect group in progress ...." -NoNewline
    $ligFile = Get-Content $Script:ReferenceFolder\lig.json -Raw | convertFrom-json
    $targetLIG = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    $targetLigId = @{}
            
    [Array]$baseLigNames = $ligFile.members.name
    [Array]$targetLigNames = $targetLIG.members.name

    [Array]$targetLigDiff = $targetLigNames | ?{-not ( $baseLigNames -contains $_ ) }
    [Array]$baseLigDiff = $baseLigNames | ?{-not ( $targetLigNames -contains $_ ) }
            
    $targetJson = $targetLIG.members | select * -ExcludeProperty  eTag,Created,status,modified,description, fabricUri,fcoeSettings,qosConfiguration,ethernetSettings
    $targetJsonLig = filterLIG $targetJson

    replaceTargetHardwareUri $ligFile

    $baseDiffLig = Get-Content $Script:ReferenceFolder\lig.json -Raw | convertFrom-json
    $baseJson = $baseDiffLig.members | select * -ExcludeProperty  eTag, Created,status,modified,description,fabricUri,fcoeSettings,qosConfiguration,ethernetSettings

    $baseJsonLig = filterLIG $baseJson
				
    if ( $baseLigDiff -and $targetLigDiff )
    {
        $pastLigUri = @{}
        $pastLigUri = Create_PreviousElement_URI $baseLigDiff $baseJsonLig $targetJson "lig.json"
        changeTarget $baseLigDiff $targetLigDiff $baseJsonLig $targetJsonLig $pastLigUri
    }
    
    if ($jsonfile.members.count -eq 0)
    {
        writeLog " LogicalInterconnect Group are empty in the base appliance "	
    }
    else
    {
        foreach ( $lig in $baseJsonLig )
        {
            $active = Get-HPOVLogicalInterconnectGroup $lig.name
            if ($active.state -eq "Active" -or $active.state -eq "Changed")
            {
                $destJson = Send-HPOVRequest -uri $active.uri GET 
                $destJsonFilter = $destJson | select * -ExcludeProperty  eTag, Created,status,modified,description,fabricUri,fcoeSettings,qosConfiguration,ethernetSettings
                $targetJson = filterLIG $destJsonFilter

                diffAttributes $lig $null $destJsonFilter $null "LIG"
                     
            }
            else
            {
           # $post = $lig | select * -ExcludeProperty  *uri*
              $post = $lig | select * -ExcludeProperty uri
            postTarget $post
            }
        }
    }
          
    start-sleep -s 5
    Write-Host "`t`t Complete!"			
}




function networkSetsReplicate()
{
	<#
        .SYNOPSIS
		Replicate Network Sets.

        .DESCRIPTION
        Replicate Network Sets.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    Write-Host "Cloning NetworkSets in progress ...." -NoNewline
	
    replaceNameToUri
    $netSetJson = Get-Content $Script:ReferenceFolder\$($path.Key) -Raw | convertFrom-json
    
    $netSet = $netSetJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description
    $targetJson = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json

    $targetSetId = @{}
    [Array]$baseSet = $netSet.name
    [Array]$targetSet = $targetJson.members.name
    [Array]$targetNetSet = $targetSet | ?{ -not ($baseSet -contains $_) }
    [Array]$baseNetSet = $baseSet | ?{ -not ($targetSet -contains $_) }

    $targetJsonFilter = $targetJson.members | select * -ExcludeProperty  eTag, Created, status, modified, description

    if ( $targetNetSet -and $baseNetSet )
    {
        $pastNetSetURI = @{}
        $pastNetSetURI = Create_PreviousElement_URI $baseNetSet $netSet $targetJsonFilter "networkset.json"
        changeTarget $baseNetSet $targetNetSet $netSet $targetJsonFilter $pastNetSetURI
       
    }
    if ( $jsonfile.members.Count -eq 0 )
    {
        writeLog "Networks Set are empty in the Base applaince "		

    }
    else
    {
        foreach ( $set in $netSet )
        {
            $active = Get-HPOVNetworkSet $set.name
            if ( $active.state -eq "Active" )
            {
                $setName = $set.name -Replace '\s',''
                $bwUri = Get-Content $Script:ReferenceFolder\NetworkSet\$setName.json -Raw | convertFrom-json
                $targetJson = Send-HPOVRequest -uri $active.uri GET
                $targetJsonFilter = $targetJson | select * -ExcludeProperty  eTag, Created, status, modified, description | ConvertTo-Json
                diffAttributes $set $bwUri $targetJsonFilter "connectionTemplateUri" "Networks"
                diffAttributes $set $null $targetJsonFilter $null "NetworkSet"
             }
            else
            {
                $post = $set | select * -ExcludeProperty  eTag, Created,status,modified,description,connectionTemplateUri,uri
                postTarget $post
            }
        }
         Write-Host "`t`t`t`t Complete!"
    }
}

function replicateEnclosure()
{
    <#
    $task = New-HPOVEnclosure -hostname "192.168.19.131" -enclGroupName "Cage-A Production Enclosures" -username "Administrator" -password "hpinvent" -licensingIntent  "OneView"
    Wait-HPOVTaskComplete $task.uri -timeout (New-TimeSpan -Minutes 10) 
    #>
    $enclGroup = Get-HPOVEnclosureGroup "Cage-A Production Enclosures"

    $import = [PSCustomObject]@{

                    hostname             = "192.168.19.131";
                    username             = "Administrator";
                    password             = "hpinvent";
					force                = $true;
                    licensingIntent      = "OneView";
                    enclosureGroupUri    = $enclGroup.uri;
                    firmwareBaselineUri  = $null;
                    forceInstallFirmware = $false;
                    updateFirmwareOn     = "EnclosureOnly" 

                }

    $resp = Send-HPOVRequest -uri "/rest/enclosures" POST $import
    $task = Wait-HPOVTaskComplete $resp.uri -timeout (New-TimeSpan -Minutes 10)
}

function displayEnclosureInfo()
{
    # Display the enclosure information
    Get-HPOVServer | ConvertTo-Json -Depth 99 | Out-File serverHW.json  
    $app = Get-HPOVApplianceNetworkConfig
    
    

    $networks = [PSCustomObject]@{

                    gateway             = $app.applianceNetworks[0].ipv4Gateway;
                    subnet             = $app.applianceNetworks[0].ipv4Subnet
                }

     $networks | ConvertTo-Json -Depth 99 | Out-File network.json

}

function replicatefirmwareBundle ( $appliances, $ip, $user, $password )
{

     
    $arrayJobs=@()

    $FilePathReference = "$Script:BaseLoc\*.iso"
    $FilePath = $FilePathReference | Get-ChildItem -rec | FoREach-Object -Process {$_.FullName}

    if($appliances)
    {
        
        foreach ($Appl in $Appliances)
        { 
        
	        $csv_ip = $Appl.serverip
	        $csv_user = $Appl.username
	        $csv_pass = $Appl.password	

            if ( $csv_ip -eq $null -or $csv_user -eq $null -or $csv_pass -eq $null)
            {
                Write-Host "Please check the input file"
            } else {

            $oneViewPsmfile="HPOneView.200.psm1" 

            $scriptblock = {
                param($FilePath)

               # Import-Module $using:oneViewPsmfile -WarningAction "SilentlyContinue" -Verbose:$false

                writeLog "DEBUG: Appliance $using:csv_ip UserName $using:csv_user Password $using:csv_pass Filepath $FilePath OneView $using:oneViewPsmfile"

                Connect-HPOVMgmt -appliance $using:csv_ip -user $using:csv_user -password $using:csv_pass

                writeLog "DEBUG: SessionId for machine $using:csv_ip is $global:cimgmtSessionId"  
                
                $firmwareName=(dir $FilePath | select basename).basename
                $exists = Send-HPOVRequest -uri "/rest/firmware-drivers/$firmwareName"

                if($exists.status -eq "OK" ) {
                    writeLog "Already Firmware exists"
                    

                }else{


                        do{


                            $task=Add-HPOVBaseline $FilePath 

                           writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") $task" 
                           writeLog "$task | ConvertTo-Json -depth 99 "
                           writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Task State: $($task.taskState)"
                           writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Resource Uri: $($task.associatedResource.resourceUri)" 

                            if($task.taskState -eq "Error" ) {
                               WriteLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Deleting the firmwarebundle located at $($task.associatedResource.resourceUri)"
                               Remove-HPOVResource -nameOrUri $task.associatedResource.resourceUri
                            
                            }

                        } while($task.taskState -eq "Error")
                    }

                }

               
                Disconnect-HPOVMgmt

                Remove-Module HPOneView.200
                }

            $arrayJobs += Start-Job -Name $csv_ip -ScriptBlock $scriptblock -ArgumentList $FilePath
        }
    

    $complete = $false
    while (-not $complete) {
        $arrayJobsInProgress = $arrayJobs | 
            Where-Object { $_.State -match 'running' }
        if (-not $arrayJobsInProgress) { "All Jobs Have Completed" ; $complete = $true } 
    }
    WriteLog "SPP Replication complete!"



    }
    else{
           # Import-Module 'HPOneView.200.psm1' -WarningAction "SilentlyContinue" -Verbose:$false
            Connect-HPOVMgmt -appliance $ip -User $user -password $password
            $firmwareName=(dir $FilePath | select basename ).basename
            $exists = Send-HPOVRequest -uri "/rest/firmware-drivers/$firmwareName"

            if($exists.status -eq "OK")
            {
                writeLog "Already Firmware Exists"               
            }else{

                $cnt=0
                do{
                   
                       $task=Add-HPOVBaseline $FilePath 

                       writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") $task" 
                       writeLog " $task | ConvertTo-Json -depth 99 "
                       writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Task State: $($task.taskState)" 
                       writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Resource Uri: $($task.associatedResource.resourceUri)"

                       if($task.taskState -eq "Error" -and $cnt -lt 1 ) {
                            writeLog "DEBUG: $(get-date -UFormat `"%Y-%m-%d %T`") Deleting the firmwarebundle located at $($task.associatedResource.resourceUri)"
                            Remove-HPOVResource -nameOrUri $task.associatedResource.resourceUri
                        }
                        $cnt += 1

                    } while($task.taskState -eq "Error" -and $cnt -le 1 )
            }
            Disconnect-HPOVMgmt
    }

}

function replaceServerHardwareUri()
{
	<#
        .SYNOPSIS
		Replace server-hardware name to target server-hardware URI.

        .DESCRIPTION
        This internal helper function Replace server-hardware name to target server-hardware URI.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>

    $serverHW = Send-HPOVRequest -uri "/rest/server-hardware-types" GET
	$sh = @{ }
	$sh = mapParameter  $serverHW.members.name $serverHW.members.uri		
	$enclosureGroup = Send-HPOVRequest -uri "/rest/enclosure-groups" GET
	$eg = @{ }
	$eg = mapParameter $enclosureGroup.members.name $enclosureGroup.members.uri
    $spTemplate = Get-Content $Script:ReferenceFolder\serverprofile_template.json -Raw | convertFrom-json
	$netSet = Send-HPOVRequest -uri "/rest/network-sets" GET
	$ns = @{ }
	$ns = mapParameter $netSet.members.name $netSet.members.uri
	$fc_net = Send-HPOVRequest -uri "/rest/fc-networks" GET
	$fc = @{ }
	$fc = mapParameter $fc_net.members.name $fc_net.members.uri
	$et_net = Send-HPOVRequest -uri "/rest/ethernet-networks" GET
	$en = @{ }
	$en = mapParameter  $et_net.members.name $et_net.members.uri
	$set_fc = mergerHashTables $en $fc
    $networks = mergerHashTables $set_fc $ns
	
    if($spTemplate.count)
    {
    					
        foreach ($sp in $spTemplate.members)
        {
	        foreach ($s in $sh.GetEnumerator())
	        {
		        if ($sp.serverHardwareTypeUri -eq $($s.Key))
		        {						
			        Replace $sp.serverHardwareTypeUri $($s.Value) "$Script:ReferenceFolder\serverprofile_template.json"						
			        break						
		        }
	        } #End of hardware type							
				
	        foreach ($e in $eg.GetEnumerator())
	        {
		        if ($sp.enclosureGroupUri -eq $($e.Key))
		        {
			        Replace $sp.enclosureGroupUri $($e.Value) "$Script:ReferenceFolder\serverprofile_template.json"
			        break
		        }
	        }    ## End of Enclosure Group
				
            foreach ( $net_name in $sp.connections.networkUri ) 
            {
		        foreach ($f in $networks.GetEnumerator())
		        {
			        if ( $net_name -eq $($f.Key))
			        {
			        Replace $net_name $($f.Value) "$Script:ReferenceFolder\serverprofile_template.json"
			        break						
		            }
	            }  }  ## End of networks				
        }

    }
}

function serverProfileTemplateReplicate ()
{
    		
	<#
        .SYNOPSIS
		Replicate Server Profile Template.

        .DESCRIPTION
        This internal helper function Replicate Server Profile Template.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    replaceServerHardwareUri
    Write-Host "Cloning Server Profile Templates in progress ...." -NoNewline

    $sptBase = Get-Content $Script:ReferenceFolder\serverprofile_template.json -Raw | convertFrom-json
    $sptTarget = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    [Array]$baseSPT = $sptBase.members.name
    [Array]$targetSPT = $sptTarget.members.name

    [Array]$baseSPTDiff = $baseSPT | ?{-not ( $targetSPT -contains $_ ) }
    [Array]$targetSPTDiff = $targetSPT | ?{-not ( $baseSPT -contains $_ ) }

    $targetJson = $sptTarget.members | select * -ExcludeProperty  eTag, Created, status, modified, cat*,state
    $baseJson = $sptBase.members | select * -ExcludeProperty  eTag, Created, status, modified, cat*,state

    if ($baseSPTDiff -and $targetSPTDiff )
    {
        $pastSPTUri = @{}
        $pastSPTUri = Create_PreviousElement_URI $baseSPTDiff $baseJson $targetJson "serverprofile_template.json"
        changeTarget $baseSPTDiff $targetSPTDiff $baseJson $targetJson $pastSPTUri
    }

    if($baseJson.Count -eq 0 )
    {
        writeLog " Server Profile Template are empty in the base appliance "
    }
    else
    {
        foreach ( $spt in $baseJson )
        {
            $active= Get-HPOVProfile $spt.name

            if ($active.state -eq "Active"  -or $active.name -eq $spt.name )
            {
                $targetSPTJson = Send-HPOVRequest -uri $active.uri GET
                $targetSPTFilter = $targetSPTJson | select * -ExcludeProperty  eTag, Created, status, modified, cat*,state
                diffAttributes $spt $null $targetSPTFilter $null "SPT"
            }
            else
            {
               $post = $spt | select * -ExcludeProperty  eTag, Created, uri, status, modified, cat*,state
               postTarget $post
            }
        }
        
    }

 
    Write-Host "`t`t Complete!"
			
} 


function filterLIG ( [Object]$ligJson)
{
	<#
        .SYNOPSIS
		Filter LIG json file.

        .DESCRIPTION
        This internal helper function Filter LIG json file.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    if( $ligJson.snmpConfiguration -and $ligJson.interconnectMapTemplate.interconnectMapEntryTemplates -and $ligJson.telemetryConfiguration )
    {

	$ligJson.snmpConfiguration | Add-Member -type NoteProperty -name created -Value ($null) -Force
	$ligJson.snmpConfiguration | Add-Member -type NoteProperty -name modified -Value ($null) -Force
	
	$ligJson.interconnectMapTemplate.interconnectMapEntryTemplates | Add-Member -type NoteProperty -name logicalDownlinkUri -Value ($null) -Force
	
	$ligJson.telemetryConfiguration | Add-Member -type NoteProperty -name created -Value ($null) -Force
	
	$ligJson.telemetryConfiguration | Add-Member -type NoteProperty -name modified -Value ($null) -Force
	$ligJson.telemetryConfiguration | Add-Member -type NoteProperty -name uri -Value ($null) -Force

    }
	
<#
	$ligJson.ethernetSettings | Add-Member -type NoteProperty -name id -Value ($null) -Force
	$ligJson.ethernetSettings | Add-Member -type NoteProperty -name uri -Value ($null) -Force
	$ligJson.ethernetSettings | Add-Member -type NoteProperty -name created -Value ($null) -Force
	$ligJson.ethernetSettings | Add-Member -type NoteProperty -name modified -Value ($null) -Force
	$ligJson.ethernetSettings | Add-Member -type NoteProperty -name dependentResourceUri -Value ($null) -Force
#>
	
	return $ligJson

}

function serverhardwaretypesReplicate ()
{

	<#
        .SYNOPSIS
		Replicate Server Profile Template.

        .DESCRIPTION
        This internal helper function Replicate Server Profile Template.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>

    Write-Host "Cloning Server hardware types in progress ...." -NoNewline

    $shtBase = Get-Content $Script:ReferenceFolder\serverhardwaretypes.json -Raw | convertFrom-json
    $shtTarget = Get-Content $Script:DestinationFolder\$($path.Key) -Raw | convertFrom-json
    [Array]$baseSHT = $shtBase.members.name
    [Array]$targetSHT = $shtTarget.members.name

    [Array]$baseshtDiff = $baseSHT | ?{-not ( $targetSHT -contains $_ ) }
    [Array]$targetshtDiff = $targetSHT | ?{-not ( $baseSHT -contains $_ ) }

    $targetJson = $shtTarget.members |  select * -ExcludeProperty  eTag, Created, status, modified, description
    $baseJson = $shtBase.members |  select * -ExcludeProperty  eTag, Created, status, modified, description

    if ( $baseshtDiff -and $targetshtDiff )
    {
        $pastSHTUri = @{}
        $pastSHTUri = Create_PreviousElement_URI $baseshtDiff $baseJson $targetJson "serverhardwaretypes.json"
        changeTarget $baseshtDiff $targetshtDiff $baseJson $targetJson $pastSHTUri

    }

    if($baseJson.Count -eq 0 )
    {
        WriteLog "Server Hardware Types are empty in the base appliance"
    }
    else
    {
        foreach ( $sht in $baseJson)
        {
            $active = Get-HPOVProfile $sht.name

            if ($active.state -eq "Active" -or $active.name -eq $sht.name )
            {
                $targeSHTJson = Send-HPOVRequest -uri $active.uri GET
                $targetSHTFilter = $targeSHTJson | select * -ExcludeProperty  eTag, Created, status, modified, description
                diffAttributes $sht $null $targetSHTFilter $null "SHT"

            }
            else
            {
               # $post = $sht | select * -ExcludeProperty  eTag, Created, status, modified, description
                postTarget $post
            }

        }
    }
    Write-Host "`t Complete!"

}

function replicateConfiguration ( $targetIP, $targetUser, $targetPassword )
{
	<#
        .SYNOPSIS
		Replicate HP-OV appliance.

        .DESCRIPTION
        This internal helper function Replicate HP-OV appliance.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>
    $returnCode = connectFusion $targetIP $targetUser $targetPassword
    validateConnection ($returnCode)
    Write-Host
	Write-Host "Replicate reference configuration to Appliance at : $targetIP "
    Write-Host

    removeTargetComponents

    foreach ($path in $uris.GetEnumerator())
    {
        $jsonfile = Get-Content $Script:ReferenceFolder\$($path.key) -Raw | convertFrom-json
        if ($($path.Key) -eq "network.json")
		{	
			networkReplicate ( $jsonfile )
            
            if($script:mode -eq "ethernet")
            {
                break
            }
                      	          
		}
        elseif ($($path.Key) -eq "fc_network.json")
		{
		    if ($jsonfile.members.count -eq 0)
			{
				writeLog " FC Networks are empty in the Base Appliance "				
			}
			else
			{
                fcNetworkReplicate ( $jsonfile )
                if($script:mode -eq "fcNetwork" )
                {
                    break
                }
                
			}		
		}
        elseif ($($path.Key) -eq "fcoe_network.json")
		{
            fcoeReplicate ( $jsonfile )
            if($script:mode -eq "fcoeNetwork")
            {
                break
            }
		
		}
		elseif ($($path.Key) -eq "networkset.json")
		{
            networkSetsReplicate
            if($script:mode -eq "networkSet")
            {
                break
            }
        } 
        elseif ($($path.Key) -eq "lig.json")
        { 		
            ligReplicate($jsonfile)
            if($script:mode -eq "lig")
            {
                break
            }
        } 		
		elseif ($($path.Key) -eq "enclosureGroup.json")
		{
            ## Enclosre ON pending
           enclosureGroupReplicate
           if($script:mode -eq "enclosureGroup")
           {
                break
           }
                       		
		} 
       	elseif ($($path.Key) -eq "serverprofile_template.json")
		{	
            replicateEnclosure
            serverProfileTemplateReplicate
            displayEnclosureInfo
            if($script:mode -eq "serverProfileTemplate")
            {
                break
            }
		}			


    }

    DisconnectFusion
    

}


function replaceServerhardwareTemplate ( $targetIP, $targetUser, $targetPassword )
{

	<#
        .SYNOPSIS
		Replicate replicate serverhardwaretemplate.

        .DESCRIPTION
        This internal helper function Replicate HP-OV appliance.

        .PARAMETER 
		None
		
        .INPUTS
        None

        .OUTPUTS
        None 
    #>

    $returnCode = connectFusion $targetIP $targetUser $targetPassword
    validateConnection ($returnCode)

    Write-Host
	Write-Host "Replicate reference configuration to Appliance at : $targetIP "
    Write-Host

    $serverHWTypes = Get-Content $Script:ReferenceFolder\\'serverhardwaretypes.json' -Raw | convertFrom-json

    $targetSHT = Get-Content $Script:TargetFolder\\'serverhardwaretypes.json' -Raw | convertFrom-json


    $uri = '/rest/server-hardware-types'

    if ( $ServerHWTypes.count )
    {

       for($index = 0; $index -lt $ServerHWTypes.count ; $index++)
       {
            $payload = $ServerHWTypes.members[$index] | Select –property 'Type','Category','Name','Description','Model','formFactor','pxeBootPolicies','bootModes','storageCapabilities','adapters','bootCapabilities','capabilities'
            [Array]$targetShtNames = $targetSHT.members.name

            if ( $targetShtNames -notcontains $payload.name)
            {

                #Modify the structure
                $capability_arr = @()
                $tmp_capability = $payload.adapters.capabilities

                for($i=0; $i -lt $tmp_capability.Count ; $i++)
                {
                    $capabilities = [pscustomobject]@{
                                                     name = $tmp_capability[$i]                                    
                                              }
                    $capability_arr += [System.Array]$capabilities
                }
    
       
               for($adpcnt = 0; $adpcnt -lt $payload.adapters.Count; $adpcnt++)    
               {
                      #Clear the capability
                      $payload.adapters[$adpcnt].capabilities = @()

                      for($prtindex =0; $prtindex -lt $payload.adapters[$adpcnt].ports.Count; $prtindex++)
                      {
                             $portObject = $payload.adapters[$adpcnt].ports[$prtindex] 
                             Add-Member -inputobject $portObject -NotePropertyName capabilities -NotePropertyValue $capability_arr 
                             $payload.adapters[$adpcnt].ports[$prtindex] = $portObject
                      }
               }
            
           # $resul = Send-HPOVRequest /rest/server-hardware-types POST $payload
            $resul = postTarget $payload "POST" /rest/server-hardware-types "SHT" 


           # Write-Host $payload.name " Return value : " $resul

        }
        else{
            $name=$payload.name
            Write-Host "Server Hardware Types <$name> already exists"
            writeLog "Server Hardware Types <$name> already exists"
            }
        }
        
    }
    else{
            Write-Host "Server Hardware Types are empty at Base Applaiance"
            writeLog "Server Hardware Types are empty at Base Applaiance"
        }

}


### Additional Helper functions ends.




# Main Command lets 

function Get-OVInventory {
	<#
        .SYNOPSIS
        Extract templates from reference appliance

        .DESCRIPTION
        This cmdlet will extract resource templates from the OneView reference appliance

        .PARAMETER 
        [System.Object] Message data
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
	Param (
		[parameter(Mandatory = $true, HelpMessage = "Enter the appliance DNS name or IP")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$ApplianceIP,
		[parameter(Mandatory = $true, HelpMessage = "Enter the user name")]
        [ValidateNotNullOrEmpty()]
		[alias("u")]
		[System.String]$UserName,
		[parameter(Mandatory = $false, HelpMessage = "Enter the password")]
        [ValidateNotNullOrEmpty()]
		[alias("p")]
		[System.String]$decryptPassword,
		[parameter(Mandatory = $true, HelpMessage = "Enter the location")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$Location
	)
	Begin {
		# Test for existence of log directory
		if(! (Test-Path -Path $Location -PathType Container))
		{
			New-Item -ItemType Directory -Path $Location
		}
	}
	Process {
		#Decrypt password
		if ($Password -eq $null){
            $Password = Read-Host "Enter the OneView appliance Password for $UserName@$ApplianceIP " -AsSecureString
            $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))            
        }
		

		Write-Host "Discover target Appliance: $ApplianceIP ... " -NoNewline
		WriteLog "Discover target Appliance: $ApplianceIP ... " 

		# Connect to the reference appliance
		$returnCode = connectFusion $ApplianceIP $UserName $decryptPassword

        validateConnection
                        
        foreach ($json in $uris.GetEnumerator())
	    {		
		    $ret_json = Send-HPOVRequest -uri $($json.Value) GET
		    $ret_json | ConvertTo-Json -depth 99 | Out-File -filepath $Location/$($json.Name)
	    }

        DisconnectFusion
        Write-Host "`t Complete!"

    }
    

}



function Get-OVTemplateConfig {
	<#
        .SYNOPSIS
        Extract templates from reference appliance

        .DESCRIPTION
        This cmdlet will extract resource templates from the OneView reference appliance

        .PARAMETER 
        [System.Object] Message data
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
	Param (
		[parameter(Mandatory = $true, HelpMessage = "Enter the appliance DNS name or IP")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$ApplianceIP,

		[parameter(Mandatory = $true, HelpMessage = "Enter the user name")]
        [ValidateNotNullOrEmpty()]
		[alias("u")]
		[System.String]$UserName,

        
		[parameter(Mandatory = $false, HelpMessage = "Enter the password")]
        [ValidateNotNullOrEmpty()]
		[alias("p")]
        [System.String]$decryptPassword,

        [parameter(Mandatory = $true, HelpMessage = "Enter the firmware")]
        [ValidateNotNullOrEmpty()]
        [System.String]$FirmwareOnOff,

        
        [parameter(Mandatory = $false, HelpMessage = "Enter the firmware")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Firmware,

		
        
		[parameter(Mandatory = $true, HelpMessage = "Enter the location")]
        [ValidateNotNullOrEmpty()]
        [alias("f")]
        [System.String]$Location      

	)
	Begin {
		# Test for existence of log directory
		if(! (Test-Path -Path $Location -PathType Container))
		{
			New-Item -ItemType Directory -Path $Location
		}

        

        $firmwareUri="http://$ApplianceIP/nossl/fwbundles"
        $url = $firmwareUri+ "/" + $Firmware
        $FileLocation = "$Location\firmwareBundle" + "\" + $Firmware
        $FilePath = $FileLocation
        isDirectory "$Location\firmwareBundle"
        
	}
	Process {
		#Decrypt password
		if (!$Password){
            $Password = Read-Host "Enter the OneView appliance Password for $UserName@$ApplianceIP " -AsSecureString
            $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))            
        }
		

		Write-Host "Discover reference Appliance: $ApplianceIP ... " -NoNewline
		WriteLog "Discover reference Appliance: $ApplianceIP ... " 

		# Connect to the reference appliance
		$returnCode = connectFusion $ApplianceIP $UserName $decryptPassword

	    validateConnection
	   	$Script:BaseFolder = $Location
        $Script:Audit = "$Location\Audit"
        isDirectory "$Script:Audit" "dir"
		
		foreach ($a in $Script:auditLogs.GetEnumerator())
        {
	        $audit = Send-HPOVRequest -uri $($a.Value) GET
	        $audit | ConvertTo-Json -Depth 99 | Out-File -FilePath $Script:Audit/$($a.Name)
        }
    	
				
		# Get All json templates from the appliance	
		foreach ($uri in $uris.GetEnumerator())
		{		
			$ret_json = Send-HPOVRequest -uri $($uri.Value) GET
			$ret_json | ConvertTo-Json -depth 99 | Out-File -filepath $Script:BaseFolder/$($uri.Name)
		}

		### Completed only till here - Will need to work on reformating code from here along with meaningful variable names

		## Get the json files Ethernet,FC, Network-Set, LIG,Enclosure Group
		$netSrc = Get-Content $Script:BaseFolder\network.json -Raw | convertFrom-json
		### Collect all URI json file 
		$netUri=@{}

		$netUri = mapParameter $netSrc.members.name $netSrc.members.connectionTemplateUri

		isDirectory "$Script:BaseFolder/Network" "dir"
		isDirectory "$Script:BaseFolder/FC_Network" "dir"
		isDirectory "$Script:BaseFolder/FCoE_Network" "dir"
    
		Create_ElementNamesJson $netUri "Network"

    
		### Collect the FC -URI's
		$fcNetSrc = Get-Content $Script:BaseFolder\fc_network.json -Raw | convertFrom-json
		$fcUris=@{}
		$fcUris = mapParameter $fcNetSrc.members.name $fcNetSrc.members.connectionTemplateUri
 
		Create_ElementNamesJson $fcUris "FC_Network"
   
		## Collect FcoE - URI
		$fcoeSrc = Get-Content $Script:BaseFolder\fcoe_network.json -Raw | convertFrom-json
		$fcoeUri=@{}
		$fcoeUri = mapParameter $fcoeSrc.members.name $fcoeSrc.members.connectionTemplateUri

		Create_ElementNamesJson $fcoeUri "FCoE_Network"

		####  Networkset.json:Replace uri to name ###########
		$netSrc = Get-Content $Script:BaseFolder\network.json -Raw | convertFrom-json
		$nameUri = @{ }

	
		$nameUri = mapParameter  $netSrc.members.name $netSrc.members.uri
		$netJsonFile = Get-Content $Script:BaseFolder\networkset.json -Raw | convertFrom-json

        if($netJsonFile.members.count)
        {

		    foreach ($value in $netJsonFile.members.networkUris.split(" "))
		    {
			    foreach ($search in $nameUri.GetEnumerator())
			    {			
				    if ($value -eq $($search.Value))
				    {								
					    Replace $value $($search.Key) "$Script:BaseFolder\networkset.json"				
				    }
			    }
		    }

        }

		isDirectory "$Script:BaseFolder/NetworkSet" "dir"
		$netSetBase = Get-Content $Script:BaseFolder\networkset.json -Raw | convertFrom-json
		$netSetUri = @{}
		$netSetUri = mapParameter $netSetBase.members.name $netSetBase.members.connectionTemplateUri

		Create_ElementNamesJson $netSetUri "NetworkSet"

	
		###### lig.json: Replace  interconnect uri to name #####
		$icJson = Send-HPOVRequest -uri "/rest/interconnect-types" GET
		$deviceUri = @{ }

	

		$deviceUri = mapParameter  $icJson.members.name  $icJson.members.uri

		### Replace  uri to Network name
		### Replace URI to FC Network
		$fcFile = Get-Content $Script:BaseFolder\fc_network.json -Raw | convertFrom-json
		$fcUri = @{ }
		$fcUri = mapParameter  $fcFile.members.name $fcFile.members.uri
	
		$ligFile = Get-Content $Script:BaseFolder\lig.json -Raw | convertFrom-json
        if($ligFile.count)
        {

		    foreach ($value in $ligFile.members.uplinkSets.networkUris.split(" "))
		    {		
			    if ($nameUri -ne 'null')
			    {			
				    foreach ($search in $nameUri.GetEnumerator())
				    {				
					    if ($value -eq $($search.Value))
					    {					
						    $dest_string = $($search.Key)+"lig"
						    Replace $value $dest_string "$Script:BaseFolder\lig.json"					
					    }
				    }
			    }
			    if ($fcUri -ne 'null')
			    {			
				    foreach ($fc in $fcUri.GetEnumerator())
				    {				
					    if ($value -eq $($fc.Value))
					    {	
						    $fcString = $($fc.Key)+"lig"				
						    Replace $value $fcString "$Script:BaseFolder\lig.json"					
					    }
				    }
			    }		
		    } #### End of Replace LIG
        }
		
        ## Replace internales URI's to name 

        $ethFC = mergerHashTables $nameUri $fcUri

        foreach ($value in $ligFile.members.internalNetworkUris )
        {
	        foreach ( $internal in $ethFC.GetEnumerator() )
	        {
		        if ( $value -eq $(($internal.value)) )
		        {
			        $targetName = $($internal.key)+"lig"
			        Replace $value $targetName "$Script:BaseFolder\lig.json"
		        }
	        }

        } ##End of internal networks
    
        
		#### Replace permitted uri to device name
	    $ligJson = Send-HPOVRequest -uri "/rest/logical-interconnect-groups" GET
       
       if($ligJson.count)
       {
		$permUri = $ligJson.members.interconnectMapTemplate.interconnectMapEntryTemplates.permittedInterconnectTypeUri

		    foreach ($value in $permUri)
		    {		
			    foreach ($search in $deviceUri.GetEnumerator())
			    {			
				    if ($value -eq $($search.Value))
				    {				
					    Replace $value $($search.Key) "$Script:BaseFolder\lig.json"
				    }
			    }
		    }
        }
	
		### Replace Enclosure Group lig uri to Name
		$enclsoureJson = Get-Content $Script:BaseFolder\enclosureGroup.json -Raw | convertFrom-json
		$ligJson = Get-Content $Script:BaseFolder\lig.json -Raw | convertFrom-json
		$ligUri = @{}
		$ligUri = mapParameter  $ligJson.members.name $ligJson.members.uri
    
        if($enclsoureJson.count)
        {

		    foreach ($uri in $enclsoureJson.members.interconnectBayMappings.logicalInterconnectGroupUri | Get-Unique)
		    {		
			    if ($uri)
			    {			
				    foreach ($lig in $ligUri.GetEnumerator())
				    {				
					    if ($uri -eq $($lig.Value))
					    {					
						    Replace $uri $($lig.Key) "$Script:BaseFolder\enclosureGroup.json"
					    }
				    }
			    }
		    }
        }
	
		### Replace Server Profile Template uri to Name
		$serverHW = Send-HPOVRequest -uri "/rest/server-hardware-types" GET
		$sh = @{ }


		$sh = mapParameter  $serverHW.members.name $serverHW.members.uri

		$enclosureGroup = Get-Content $Script:BaseFolder\enclosureGroup.json -Raw | convertFrom-json
		$eg = @{ }

		$eg = mapParameter  $enclosureGroup.members.name $enclosureGroup.members.uri
    
		$netSet = Get-Content $Script:BaseFolder\networkset.json -Raw | convertFrom-json
		$ns = @{ }

		$ns = mapParameter $netSet.members.name $netSet.members.uri
       
		$fcNetSet = mergerHashTables $ns $fcUri
		$network = mergerHashTables $fcNetSet $nameUri
		$spTemplate = Get-Content $Script:BaseFolder\serverprofile_template.json -Raw | convertFrom-json
	
        if($spTemplate.count)
        {

		    foreach ($sp in $spTemplate.members)
		    {		
			    if ($sp.serverHardwareTypeUri.split("/")[2] -eq "server-hardware-types")
			    {			
				    foreach ($s in $sh.GetEnumerator())
				    {
					    if ($sp.serverHardwareTypeUri -eq $($s.Value))
					    {					
						    Replace $sp.serverHardwareTypeUri $($s.Key) "$Script:BaseFolder\serverprofile_template.json"
						    break					
					    }
				    }
			    } #End of hardware type
		
			    if ($sp.enclosureGroupUri.split("/")[2] -eq "enclosure-groups")
			    {
				    foreach ($e in $eg.GetEnumerator())
				    {
					    if ($sp.enclosureGroupUri -eq $($e.Value))
					    {
						    Replace $sp.enclosureGroupUri $($e.Key) "$Script:BaseFolder\serverprofile_template.json"
						    break
					    }
				    }
			    } ## End of Enclosure Group
		
		
			    foreach ( $uri in $sp.connections.networkUri ) 
			    {
				      foreach ($set in $network.GetEnumerator())
				     {

					    if ($uri -eq $($set.Value))
					    {
						    Replace $uri $($set.Key) "$Script:BaseFolder\serverprofile_template.json"
						    break
					    }
				    }
			    }
            }
	
		}  ### End of Replace server profile template


        #
        # Download Firmware Bundle from the applaince
        #

        if ( $FirmwareOnOff -eq "ON" -or $FirmwareOnOff -eq "On" -or $FirmwareOnOff -eq "on" )
        {

            if ( Test-Path $FilePath) 
            {
                 writeLog " SPP File already exists..."

            }else { 
                writeLog "Downloading SPP File..."			
			    try
			    {
				    $webClient = New-Object System.Net.WebClient
				    $webClient.DownloadFile($url, $FilePath)
			    }
			    catch
			    {
			        writeLog "$_.Exception" -debuglevel "ERROR"				
				    writeLog "$_.Exception.Message" -debuglevel "ERROR"
			    }			
            } 

        }

		DisconnectFusion
	
		Write-Host "`t Complete!"
		
	}
}

function Send-OVSyncServerHardware
{
	<#
        .SYNOPSIS
        Extract templates from reference appliance

        .DESCRIPTION
        This cmdlet will replicate the server hardware template from base to target applaince

        .PARAMETER 
        [System.Object] Message data
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
    Param( 
        [parameter(Mandatory = $true, HelpMessage = "Enter the Reference location")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$ReferenceLocation,

        [parameter(Mandatory = $true, HelpMessage = "Enter the Reference location")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$TargetLocation,

        [System.String]$InventoryList,
		[parameter(Mandatory = $false, HelpMessage = "Enter the appliance DNS name or IP")]
        [ValidateNotNullOrEmpty()]

		[System.String]$TargetIP ,
		[parameter(Mandatory = $False, HelpMessage = "Enter the Target IP ")]
        [ValidateNotNullOrEmpty()]
		

        [System.String]$Username,
		[parameter(Mandatory = $False, HelpMessage = "Enter the password")]
        [ValidateNotNullOrEmpty()]
		[alias("u")]
		[System.String]$Password       

       )


        Process {

            $Script:ReferenceFolder = $ReferenceLocation
            $Script:TargetFolder = $TargetLocation
            if (!$Password)
            {
               [System.Security.SecureString]$Password = Read-Host "Enter the OneView appliance Password for $Username@$TargetIP " -AsSecureString
                $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))            
            }

            if($InventoryList)
            {
                $Appliance = Import-csv $InventoryList

                foreach ($Appl in $Appliance )
                {
                $csv_ip = $Appl.serverip
		        $csv_user = $Appl.username
		        $csv_pass = $Appl.password
                    if ( $csv_ip -eq $null -or $csv_user -eq $null -or $csv_pass -eq $null )
                    {
                        Write-Host " Please verify the Inventory File "
                        exit
                    }

                    replaceServerhardwareTemplate $csv_ip $csv_user $csv_pass


                }

            }
            else{
                    replaceServerhardwareTemplate $TargetIP $Username $decryptPassword

            }
            

        }

    
     


}

function Send-OVAllChanges
{
	<#
        .SYNOPSIS
        Extract templates from reference appliance

        .DESCRIPTION
        This cmdlet will extract resource templates from the OneView reference appliance

        .PARAMETER 
        [System.Object] Message data
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
	Param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the Reference location")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$ReferenceLocation,
        [parameter(Mandatory = $false, HelpMessage = "Enter the Target location")]
        [ValidateNotNullOrEmpty()]		
		[System.String]$TargetLocation,
        [parameter(Mandatory = $false, HelpMessage = "Enter the input file/Inventory location")]
        [ValidateNotNullOrEmpty()]	
        	
		[System.String]$InventoryList,
		[parameter(Mandatory = $false, HelpMessage = "Enter the appliance DNS name or IP")]
        [ValidateNotNullOrEmpty()]
                		
		[System.String]$TargetIP,
		[parameter(Mandatory = $false, HelpMessage = "Enter the user name")]
        [ValidateNotNullOrEmpty()]
		[alias("u")]

		[System.String]$TargetUser,
		[parameter(Mandatory = $false, HelpMessage = "Enter the password")]
        [ValidateNotNullOrEmpty()]
		[alias("p")]
		[System.String]$decryptPassword,
        
         
        [parameter(Mandatory = $true, HelpMessage = "Enter the firware status On or Off ")]
        [ValidateNotNullOrEmpty()]
        [System.String]$firmwareOnOff,

        [parameter(Mandatory = $true, HelpMessage = "Enter the mode of replication")]
        [ValidateNotNullOrEmpty()] 
        [System.String]$mode
        
      
 	)
	Begin {

        
		# Test for existence of log directory
        if (!(Test-Path -Path $ReferenceLocation))
	    {
		    Write-Host " Reference Folder doesnot exists."
            exit 
	    }
        $script:mode=$mode
        $Script:DestinationFolder = $TargetLocation
        $Script:ReferenceFolder = $ReferenceLocation
        $Script:Temp = $TargetLocation+"\Temp"

        isDirectory  "$Script:Temp" "dir"
        }
		
    Process {
		#Decrypt password
		if (!$Password){
            $Password = Read-Host "Enter the OneView appliance Password for $TargetUser@$TargetIP " -AsSecureString
            $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))            
        }
		      

        if ( $InventoryList )
        {
            $Appliances = Import-csv $InventoryList

            if ( $firmwareOnOff -eq "On" -or $firmwareOnOff -eq "ON" -or $firmwareOnOff -eq "on" )
            {
                replicatefirmwareBundle $Appliances $null $null $null
            }

            foreach ($Appl in $Appliances )
            {
                $csv_ip = $Appl.serverip
		        $csv_user = $Appl.username
		        $csv_pass = $Appl.password
                if ( $csv_ip -eq $null -or $csv_user -eq $null -or $csv_pass -eq $null )
                {
                    Write-Host " Please verify the Inventory File "
                    exit
                }
                $Script:DestinationFolder=".\$csv_ip"
                $Script:ReferenceFolder = "$Script:DestinationFolder\Base" 
                isDirectory $Script:ReferenceFolder "dir"
                $Script:Temp = $DestinationFolder+"\Temp"
                isDirectory  "$Script:Temp" "dir"

                Copy-Item $ReferenceLocation\* $Script:ReferenceFolder -Recurse -Force

              #  Copy-Item $Script:ReferenceFolder\* $Script:DestinationFolder\Base -Recurse -Force

                replicateConfiguration $csv_ip $csv_user $csv_pass
            } 
        }
        else{
            $Script:ReferenceFolder = "$Script:DestinationFolder\Base"  
            isDirectory $Script:ReferenceFolder "dir"
            Copy-Item $ReferenceLocation\* $Script:ReferenceFolder -Recurse -Force -Exclude firmwareBundle
            $Script:BaseLoc = $ReferenceLocation +'\' +"firmwareBundle"
             
            if ( $firmwareOnOff -eq "On" -or $firmwareOnOff -eq "ON" -or $firmwareOnOff -eq "on" )
            {
                replicatefirmwareBundle $null $TargetIP $TargetUser $decryptPassword
            }
            replicateConfiguration $TargetIP $TargetUser $decryptPassword
        }
   
	}

}

function Remove-OVAllResources
{
	<#
        .SYNOPSIS
        Remove all resources from HP-OV Appliance 

        .DESCRIPTION
        This cmdlet will Delete all OV resources on the appliance

        .PARAMETER 
        [System.Object] mode All|ethernet|fcNetwork|fcoeNetwork|networkSet|lig|enclosureGroup|serverProfileTemplate
	    [System.String] Message Type [INFO:DEBUG:WARNING:ERROR]

        .INPUTS
        None.

        .OUTPUTS
        None       
    #>
    

Param (
   

    [parameter(Mandatory = $True, HelpMessage = "Enter the appliance DNS name or IP")]
    [ValidateNotNullOrEmpty()]	
    [System.String]$ApplianceIP,

	[parameter(Mandatory = $True, HelpMessage = "Enter the user name")]
    [ValidateNotNullOrEmpty()]
	[alias("u")]
	[System.String]$UserName,
	[parameter(Mandatory = $false, HelpMessage = "Enter the password")]
    [ValidateNotNullOrEmpty()]
	[alias("p")]
	[System.String]$decryptPassword,
    [parameter(Mandatory = $true, HelpMessage = "Enter the deletion mode")]
    [ValidateNotNullOrEmpty()]	
    [System.String]$mode
    	  
    )


    Process {

    if (!$Password)
    {
        $Password = Read-Host "Enter the OneView appliance Password for $UserName@$ApplianceIP " -AsSecureString
        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))            
    }

    Write-Host "Deleting $mode in Progress ... " -NoNewline
    writeLog "Deleting $mode in Progress ... " 

    $returnCode = connectFusion $ApplianceIP $UserName $decryptPassword
    validateConnection

    foreach ($del in $deleteAll.GetEnumerator() )
    {

        deleteHPOV ($($del.key)) ($($del.Value))
        
            
       if(($($del.key)) -contains $mode)
       {
            break
       }


    }
    DisconnectFusion
   

    Write-Host "`t`t`t`t Complete!"
  #  writeLog "Deleting $mode completes"
  }

}



Export-ModuleMember -Function Get-OVTemplateConfig -WarningAction "SilentlyContinue" -Verbose:$false
Export-ModuleMember -Function Get-OVInventory -WarningAction "SilentlyContinue" -Verbose:$false
Export-ModuleMember -Function Send-OVAllChanges -WarningAction "SilentlyContinue" -Verbose:$false
Export-ModuleMember -Function Remove-OVAllResources -WarningAction "SilentlyContinue" -Verbose:$false
Export-ModuleMember -Function Send-OVSyncServerHardware -WarningAction "SilentlyContinue" -Verbose:$false