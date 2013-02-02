#$proc = import-module C:\modules\SysTools.psm1 -ascustomobject
#or
#import-module C:\modules\SysTools.psm1

#######
#Script gobals
#######
$procs = $null 		#Get-ProcessTree
$t_proc = $null		#Get-ProcessTree
$nl = "`r`n"

#######
# C# Code for Types
#######
$netapi32 = @’
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public class NetAPI32{
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct FILE_INFO_3
{
   public int fi3_id;
   public int fi3_permission;
   public int fi3_num_locks;
   [MarshalAs(UnmanagedType.LPWStr)]
   public string fi3_pathname;
   [MarshalAs(UnmanagedType.LPWStr)]
   public string fi3_username;
}

[DllImport("netapi32.dll",CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetFileEnum(
     string servername,
     string basepath,
     string username,
     int level,
     ref IntPtr fileinfos,
     int prefmaxlen,
     out int entriesread,
     out int totalentries,
     IntPtr resume_handle);
}
‘@

#######
#Private Functions
#######
Function _ExceptionHandler {
	param ([Object]$except)
	Write-Host "[-] Exception in:" $except.InvocationInfo.ScriptName -foregroundcolor Red
	Write-Host "[-] Type: " $except.Exception.GetType().FullName -foregroundcolor Red
	Write-Host "[-] Message: " $except.Exception.Message -foregroundcolor Red
	Write-Host "[-] Location: " $except.InvocationInfo.PositionMessage -foregroundcolor Red
}

function _OutputProc ($proc, $depth) {
	$selproc = $procs|where {$_.processid -eq $proc}
	$outtext = ("`t"*$depth) + $selproc.name + " -> " + $selproc.processid + "`r`n"
	$Script:t_proc += $outtext
	$childproc = $procs|where {$_.parentprocessid -eq $proc -and $_.processid -ne $proc}|foreach {_outputproc $_.processid ($depth + 1)}
}

Function _GetDrives {
	param ([string]$target)
	Get-WmiObject Win32_LogicalDisk -computername $target |where {$_.Size -gt 0} |ForEach-Object {
			"`tLogical Disk: " + $_.deviceid + $nl
			"`tType: " + $_.drivetype + $nl
		"`tPath:" + $_.Providername + $nl
			"`tSize: " + $_.size + $nl
		if ($_.drivetype -lt 4){
			$strDriveDeviceID = $_.deviceid
			$query1 = "Associators of {Win32_LogicalDisk.DeviceID='$strDriveDeviceID'} Where AssocClass=Win32_LogicalDiskToPartition"
			$colPartitions = get-wmiobject -computername $target -query $query1 -ErrorAction SilentlyContinue
			$colPartitions | ForEach-Object {
					"`tDisk Partition: " + $_.DeviceID + $nl
					$strPartitionDeviceID = $_.DeviceID 
					$query2 = "Associators of {Win32_DiskPartition.DeviceID='$strPartitionDeviceID'} Where AssocClass=Win32_DiskDriveToDiskPartition"
					$colPDisks = Get-WmiObject -computername $target -query $query2 -ErrorAction SilentlyContinue
					$colPDisks | ForEach-Object {
						"`tPhysical Disk:" +  $_.caption + " -- " + $_.deviceid + $nl
						"`tMedia Type:" + $_.MediaType + $nl
						"`tMedia Loaded:" + $_.MediaLoaded + $nl
					}
			}
		}
	$nl
	}
}

#######
#Public Functions
#######

function Get-STProcTree {
	<#
	  .Synopsis
		Gets process listing for remote machines in "Tree-View" format
	   .Description
		Gets process listing for remote machines in "Tree-View" format. 
		
		This returns a text blob and not a custom PS Object like the other Get-ST functions displaying teh tree with Process name and PID.
	   .Example
		Get-STProcTree "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	 #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	try {
		$pids = @()
		$procs = gwmi win32_process -computername $target
		$procs|foreach {$pids += $_.processid}
		$procs|foreach {
			if ($pids -notcontains $_.parentprocessid -Or $_.parentprocessid -eq $_.processid) {_OutputProc $_.processid 0}
		}
	}
	catch {
		_ExceptionHandler $_
	}
	return $Script:t_proc
}

function Get-STProcess {
	<#
	  .Synopsis
		Gets process listing in long format
	   .Description
		Gets process listing for remote machines in long format. This is similar to Get-Process, but with the benefit of additional information with regard to the command used to execute it, the owner, and the underlying services. 
		
		Displays: caption, processid, parentprocessid, sessionid, handle, owner, commandline, threadcount, handlecount, workingsetsize, services
	   .Example
		Get-STProcess "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	 #>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$retobj = $null
	try {
		$procs = gwmi win32_process -computername $target
		$servs = gwmi -query ("select name, ProcessID from win32_service") -computername $target
		$retobj = $procs|Foreach {
				$names = @()
				$owner = $null
				$pid = $_.processid
				$cap = $_.Caption
			try {
				if ($pid -gt 2) { 
					$servs|where {$_.ProcessID -eq $pid}|foreach{$names += $_.name}
					$owner = $_.GetOwner()
				} 
			}
			catch {
				Write-Host "Error occurred getting owner or service for: $cap" -ForegroundColor Red
			}
			Add-Member -MemberType NoteProperty -Name "Services" -Value "$names" -InputObject $_ -PassThru -force
			Add-Member -MemberType Noteproperty -name "Owner" -value $("{0}\{1}" -f $owner.Domain, $owner.User) -InputObject $_ -force	
		} 
		$retobj = $retobj|select caption, processid, parentprocessid, sessionid, handle, owner, commandline, threadcount, handlecount, workingsetsize, services
	}
	catch {
		_ExceptionHandler $_
	}
	return $retobj
}

function Get-STRemFiles {
	<#
	  .Synopsis
		Gets all files opened remotely
	   .Description
		Gets all files opened remotely on a remote machine via Win32 API calls. 
		
		Displays: fileid, pathname, user, permissions
	   .Example
		Get-STRemFiles "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)

	$perms = @{1 = "Read" ; 2 = "Write" ; 4 = "Create"}
	$resume_handle=[IntPtr]::Zero
	$fi3ptr=[IntPtr]::Zero
	$entriesread=0
	$totalentries=0
	$colobj = @()

	try {
		#add our type/class
		Add-Type -TypeDefinition $Script:netapi32
		
		#call the function to get a pointer to teh return data 
		$errnum = [NetAPI32]::NetFileEnum($target,$null,$null,3,[ref]$fi3ptr,-1,[ref]$entriesread,[ref]$totalentries,$resume_handle)
		if ($errnum -eq 0) {
			#All this business is neccesary b/c PS can't parse the ptr to array of struct correctly 
			#and passing an array of structs to teh output param in the C# failed as well
			#[NetAPI32+FILE_INFO_3[]]$fileinfos=$null
			[IntPtr]$ptr = $fi3ptr
			for($i=0; $i -lt $entriesread; $i++) {
				#parse out the info based on the struct
				#$fileinfos += [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[NetAPI32+FILE_INFO_3])
				$fileinfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[NetAPI32+FILE_INFO_3])

				#create a hash object and populate it, including the bitwise AND on the perms
				$robj = @{}
				$robj.fileid = $fileinfo.fi3_id
				$robj.pathname = $fileinfo.fi3_pathname
				$robj.username = $fileinfo.fi3_username
				$robj.permissions = ""
				$perms.Keys | where { $_ -band $fileinfo.fi3_permission } | foreach { $robj.permissions += ($perms.Get_Item($_) + " ") }
				$colobj += new-object PSObject -property $robj
				
				#incriment out ptr so we can grab the next struct
				[IntPtr]$ptr = $ptr.ToInt64() +[System.Runtime.InteropServices.Marshal]::SizeOf([NetAPI32+FILE_INFO_3])	
			}
		}
		else {
			write-host "WIN32 Error: $errnum" -ForegroundColor Red
		}
	}
	catch {
		_ExceptionHandler $_
	}
	return $colobj
}

Function Get-STSysInfo {
	<#
	  .Synopsis
		Gets basic system information
	   .Description
		Gets basic system information from a remote machine including: Hardware details, OS details, Time Zone, IE & Java versions, Net Adapters, and Disks (physical, usb, and mapped).
		
		This returns a text blob and not a custom PS Object like the other Get-ST functions
	   .Example
		Get-STSysInfo "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$ouput = $null
	try {
		#registry stuff
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
		$regKey = $reg.OpenSubKey("SOFTWARE\Microsoft\Internet Explorer")

		#versions
		$IeVer = $regKey.GetValue("Version")
		$JavaVer = (get-item "\\$target\c$\program files\java\jre6\bin\java.exe").VersionInfo.ProductVersion 
		
		#WMI Crap
		$os = gwmi Win32_OperatingSystem -computername $target
		$cs =  gwmi Win32_ComputerSystem -computername $target
		$nics = gwmi Win32_NetworkAdapterConfiguration -ComputerName $target|where {$_.IPEnabled}
		
		$output = ""
		$output += "Computer System info:" + $nl
		$output += "=====================" + $nl 
		$output += "`tName:`t`t" + $cs.Name + $nl
		$output += "`tDomain:`t`t" + $cs.Domain + $nl
		$output += "`tTime Zone:`t" + ($cs.CurrentTimeZone/60) + "hrs from GMT" + $nl
		$output += "`tManufacturer:`t" + $cs.Manufacturer + $nl
		$output += "`tModel:`t`t" + $cs.Model + $nl
		$output += "`tProcessors:`t" + $cs.NumberOfProcessors + $nl
		$output += "`tLogical Proc.:`t" + $cs.NumberOfLogicalProcessors + $nl
		$output += $nl
		
		$output += "Operation System info:" + $nl
		$output += "======================" + $nl
		$output += "`tOS Name:`t" + $os.Caption + $nl
		$output += "`tBuild type:`t" + $os.Buildtype + $nl
		$output += "`tBuild Number:`t" + $os.BuildNumber + $nl
		$output += "`tVersion:`t" + $os.Version + $nl
		$output += "`tSerial Number:`t" + $os.serialNumber + $nl
		$output += "`tSystem Root:`t" + $os.SystemDirectory + $nl
		$output += "`tLast Boot:`t" + $os.ConvertToDateTime($os.LastBootupTime) + $nl
		$output += $nl
		
		$output += "Application Versions:" + $nl
		$output += "=====================" + $nl
		$output += "`tJava:`t" + $JavaVer + $nl
		$output += "`tIE:`t" + $IeVer + $nl
		$output += $nl 
		
		$output += "Adapter Settings:" + $nl
		$output += "====================="
		$output += $nics| format-list -Property @{Expression={$_.Description};Label="`t`tDescription"},
				@{Expression={$_.MacAddress};Label="`t`tMAC Address"},
				@{Expression={$_.IpAddress};Label="`t`tIP Address"},
				@{Expression={$_.IpSubnet};Label="`t`tSubnet"},
				@{Expression={$_.DefaultIpGateway};Label="`t`tDefault Gateway"}, 
				@{Expression={$_.DNSServerSearchOrder};Label="`t`tDNS Servers"}, 
				@{Expression={$_.DHCPEnabled};Label="`t`tDHCP Enabled"}|out-string
			
		$output += "Disk Info:" + $nl
		$output += "=====================" + $nl
		$output += _GetDrives $target
		$output += $nl
	}
	catch {
		_ExceptionHandler $_
	}
	return $output
}

function Get-STSoft {
	<#
	  .Synopsis
		Gets installed software
	   .Description
		Gets installed software from a remote machine via remoting. Remoting must be working and you 
		must have appropriate persissions for this to function properly. 
		
		Displays: DisplayName, DisplayVersion, Publisher, URLInfoAbout, InstallDate, and InstallLocation
	   .Example
		Get-STSysInfo "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$soft = $null
	try {
		$pso = New-PSSessionOption -NoMachineProfile
		$sb = {
			$unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
			$unistallWow6432Path ="\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
			$obj = @(
			if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path"}
			if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
			if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
			if (Test-Path "HKCU:$unistallPath" ) {Get-ChildItem "HKCU:$unistallPath" }
			)
			 $obj|foreach {Get-ItemProperty $_.PSPath }|where {$_.DisplayName}|select DisplayName, DisplayVersion, Publisher, URLInfoAbout, InstallDate, InstallLocation
		}

		$soft = invoke-command -SessionOption $pso -computername $target -scriptblock $sb
	}
	catch {
		_ExceptionHandler $_
	}
	return $soft
}

function Get-STDll {
	<#
	  .Synopsis
		Gets Loaded dlls
	   .Description
		Gets Loaded dlls by process from a remote machine. Note that thsi is similar to modules returned froma  call to Get-Process, but you cannot call Get-Process on remote machines so the WMI calls are neccesary.
		
		Displays: Name, Extension, Hidden, Manufacturer, Version, CreationDate, LastAccessed, ProcessName, ProcessId
		
		As a side note, the Hidden and CreationDate values are quite useful for identifying malicious dll's
	   .Example
		Get-STSysInfo "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$dlls = @()
	try {
		$proc = gwmi Win32_Process -computername $target 
		foreach ($p in $proc) {
			$files = gwmi -computername $target -erroraction silentlycontinue -query "Associators of {$p} where AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile"|select Name,Extension,Hidden, Manufacturer,Version,CreationDate, LastAccessed
			foreach ($f in $files) {
			if ($f){
				$f.creationdate = ([wmi]"").ConvertToDateTime($($f.creationdate))
				$f.LastAccessed = ([wmi]"").ConvertToDateTime($($f.LastAccessed))
				Add-Member -MemberType NoteProperty -Name "ProcessNa" -Value $p.name -InputObject $f -force
				Add-Member -MemberType NoteProperty -Name "ProcessId" -Value $p.ProcessId -InputObject $f -force
				$dlls += $f
				}
			}
		} 
	}
	catch {
		_ExceptionHandler $_
	}
	return $dlls
}

function Get-STService {
	<#
	  .Synopsis
		Gets Services Running 
	   .Description
		Gets Services Running on a remote machine. Note that this is similar to 
		Get-Service, but with additional data returned for analysis. 
		
		Displays: caption, name, startname, state, processid, startmode, pathname, description
		
		As a side note, the pathname are quite useful for identifying malicious services
	   .Example
		Get-STService "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$robj = $null
	try {
		$srvlist = gwmi -computername $target win32_service
		$robj = $srvlist|select caption, name, startname, state, processid, startmode, pathname, description
	}
	catch {
		_ExceptionHandler $_
	}
	return $robj
}

Function Get-STUserProf {
	<#
	  .Synopsis
		Gets user profiles  
	   .Description
		Gets user profiles and other related information from a remote machine. The 'serv_path field 
		is the remote profile path if there is one and the 'dt_time' is the last time that profile
		was accessed. 
		
		Displays: sid, localpath, servpath, user
		
	   .Example
		Get-STUserProf "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$colusers = @()
	$key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
	try {
		#set our base key
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
		
		$subkeys = $reg.OpenSubKey($key).GetSubKeyNames()
		foreach ($subkey in $subkeys){
			$sobj = [wmi]"\\$target\root\cimv2:win32_SID.SID='$subkey'"
			$hashu = @{}
			$hashu.sid = $subkey
			$hashu.localpth = $reg.OpenSubKey($($key + "\" + $subkey)).GetValue("ProfileImagePath")
			$hashu.servpath = $reg.OpenSubKey($($key + "\" + $subkey)).GetValue("CentralProfile")
			$hashu.dt_time = (Get-Item ("\\" + $target + "\c$\" + $hashu.localpth.substring(3) + "\ntuser.dat") -force).lastwritetime
			$hashu.user = "$($sobj.ReferencedDomainName)\$($sobj.AccountName)"
			$colusers += new-object PSObject -property $hashu
		}
	}
	catch {
		_ExceptionHandler $_
	}
	return $colusers
}

Function Get-STUserSess {
	<#
	  .Synopsis
		Gets user logon sessions  
	   .Description
		Gets user logon sessions and other related information from a remote machine. The data
		returned consists of all logon sessions and doe not distinguish between stale and active
		
		Displays: LogonType, LogonID, LogonName, StartTime
		
	   .Example
		Get-STUserSess "mytestbox-1" 
	   .Parameter target
		The machine to execute against
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target
	)
	$ltype = ConvertFrom-StringData -StringData @'
0 = System
2 = Interactive
3 = Network
4 = Batch
5 = Service
6 = Proxy
7 = Unlock
8 = NetworkCleartext
9 = NewCredentials
10 = RemoteInteractive
11 = CachedInteractive
12 = CachedRemoteInteractive
13 = CachedUnlock
'@
	$colusers = @()
	try {
		$ulogged = Get-WmiObject Win32_LoggedOnUser -ComputerName $target

		foreach ($u in $ulogged) {
			$hashu = @{}
			$user = $u.Antecedent.tostring().split('"')[1]
			$domain = $u.Antecedent.tostring().split('"')[3]
			$logonid = $u.Dependent.tostring().split('"')[1]
			
			#get logon type and start time from underlying session
			$l = gwmi -ComputerName $target -query "select LogonType,StartTime from Win32_Logonsession where logonid=$($logonid)"
			
			#add it all to our hash and add to tehlist of objs
			$hashu.LogonType = $ltype["$($l.LogonType)"]
			$hashu.LogonId = $logonid
			if ($l.StartTime) {
				try { $hashu.StartTime = $u.ConvertToDateTime($l.StartTime) }
				catch { $hashu.StartTime = $null }
			}
			$hashu.LogonName = "$user\$domain"
			$colusers += new-object PSObject -property $hashu
		}
	}
	catch {
		_ExceptionHandler $_
	}
	return $colusers
}

function Get-STDataDump {
	<#
	  .Synopsis
		Runs all of the SysTools functions  
	   .Description
		Executes all of the SysTools functions against a remote machine and optionally exports the data to the specified directory. The return value is a Hash object that contains the results of each function. Note the info below is assuming you are running it and putting the results in $data variable. It could be any variable, just note it doesn't have to be $data. For example $data = Get-STDataDump -target "MyTest" -outdir "C:\datacapture" -fulldump $true would return the following:
			$data.process -> contains the results from Get-STProcess 
			$data.pstree -> contains the results from  Get-STProcTree 
			$data.remfiles -> contains the results from  Get-STRemFiles 
			$data.service -> contains the results from  Get-STervice 
			$data.soft -> contains the results from  Get-STSoft 
			$data.info -> contains the results from  Get-STSysInfo 
			$data.profiles -> contains the results from  Get-STUserProf 
			$data.sessions -> contains the results from  Get-STUserSess 
			$data.dll -> contains the results from  Get-STDll
			
		It would create the appropriate data dumps in either csv or text depending on the type of data in 'C:\datacapture'.
		
		Note: If you omit the -fulldump paramter it will not run the Get-STDll
		
		
	   .Example
		Get-STDataDump -target "mytestbox-1" -outdir "C:\datacapture" 
	   .Parameter target
		The machine to execute against
	   .Parameter outdir
		The path to dump the data with out the training '\'
	   .Parameter fulldump
		A boolean value that indicates whether or not to dump dll's. To dump the loaded dll's takes about 90 to 120 seconds, so this is an option to not do that one. Default is $false, set it to $true to get the loaded dll's.
	 #Requires -Version 2.0
	#>
    [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
		[string]$target,
		[string]$outdir=$null,
		[bool]$fulldump=$false
	)
	$data = @{}
	write-host "Running Get-STProcess against $($target)...." -ForegroundColor Green
	$data.process = Get-STProcess $target
	write-host "Running Get-STProcTree against $($target)...." -ForegroundColor Green
	$data.pstree = Get-STProcTree $target
	write-host "Running Get-STRemFiles against $($target)...." -ForegroundColor Green
	$data.remfiles = Get-STRemFiles $target
	write-host "Running Get-STService against $($target)...." -ForegroundColor Green
	$data.service = Get-STService $target
	write-host "Running Get-STSoft against $($target)...." -ForegroundColor Green
	$data.soft = Get-STSoft $target
	write-host "Running Get-STSysInfo against $($target)...." -ForegroundColor Green
	$data.info = Get-STSysInfo $target
	write-host "Running Get-STUserProf against $($target)...." -ForegroundColor Green
	$data.profiles = Get-STUserProf $target
	write-host "Running Get-STUserSess against $($target)...." -ForegroundColor Green
	$data.sessions = Get-STUserSess $target
	
	if ($fulldump) {
		write-host "Running Get-STDll against $($target)...." -ForegroundColor Green
		$data.dll = Get-STDll $target
	}
	
	if (test-path $outdir) {
		write-host "Exporting your results to $($outdir)...." -ForegroundColor Green
		if ($data.process) { $data.process|Export-csv "$outdir\process.csv" }
		if ($data.pstree) { $data.pstree|out-file "$outdir\pstree.txt" }
		if ($data.remfiles) { $data.remfiles|Export-csv "$outdir\remfiles.csv" }
		if ($data.service) { $data.service|Export-csv "$outdir\service.csv" }		
		if ($data.soft) { $data.soft|Export-csv "$outdir\soft.csv" }
		if ($data.info) { $data.info|out-file "$outdir\info.txt" }
		if ($data.profiles) { $data.profiles|Export-csv "$outdir\profiles.csv" }
		if ($data.sessions) { $data.sessions|Export-csv "$outdir\sessions.csv" }
		if ($data.dll) { $data.dll|Export-csv "$outdir\dll.csv" }
	
	}
	
	return $data
}


Export-ModuleMember Get-STProcTree
Export-ModuleMember Get-STProcess
Export-ModuleMember Get-STRemFiles
Export-ModuleMember Get-STSysInfo
Export-ModuleMember Get-STSoft
Export-ModuleMember Get-STDll
Export-ModuleMember Get-STService
Export-ModuleMember Get-STUserProf
Export-ModuleMember Get-STUserSess
Export-ModuleMember Get-STDataDump





