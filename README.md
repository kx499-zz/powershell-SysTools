powershell-SysTools
===================

A PowerShell module that includes an array of system tools for interrogating remote machines. These are implimented via
functions that follow the Get-ST* format. These functions mimic a lot of the functionality of Syinternals PSTools, with
some ehancements I needed for various tasks I was doing. There are 9 functions that query a remote system for
system/user/software information:
  Get-STDll
  Get-STProcess
  Get-STProcTree
  Get-STRemFiles
  Get-STService
  Get-STSoft
  Get-STSysInfo
  Get-STUserProf
  Get-STUserSess
  
And another function that will run them all and return a hash object contaiing all the returned objects and optionally 
exporting those to a specified directory:
  Get-STDataDump
  
Here are the details:

NAME
    Get-STDll

SYNOPSIS
    Gets Loaded dlls


SYNTAX
    Get-STDll [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets Loaded dlls by process from a remote machine. Note that thsi is similar to modules returned froma  call to Get-Process, but you cannot call Get-Process on remote machines so the WMI calls ar
    e neccesary.

    Displays: Name, Extension, Hidden, Manufacturer, Version, CreationDate, LastAccessed, ProcessName, ProcessId

    As a side note, the Hidden and CreationDate values are quite useful for identifying malicious dll's
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STProcess

SYNOPSIS
    Gets process listing in long format


SYNTAX
    Get-STProcess [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets process listing for remote machines in long format. This is similar to Get-Process, but with the benefit of additional information with regard to the command used to execute it, the owner, a
    nd the underlying services.

    Displays: caption, processid, parentprocessid, sessionid, handle, owner, commandline, threadcount, handlecount, workingsetsize, services
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STProcTree

SYNOPSIS
    Gets process listing for remote machines in "Tree-View" format


SYNTAX
    Get-STProcTree [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets process listing for remote machines in "Tree-View" format.

    This returns a text blob and not a custom PS Object like the other Get-ST functions displaying teh tree with Process name and PID.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STRemFiles

SYNOPSIS
    Gets all files opened remotely


SYNTAX
    Get-STRemFiles [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets all files opened remotely on a remote machine via Win32 API calls.

    Displays: fileid, pathname, user, permissions
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STService

SYNOPSIS
    Gets Services Running


SYNTAX
    Get-STService [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets Services Running on a remote machine. Note that this is similar to
    Get-Service, but with additional data returned for analysis.

    Displays: caption, name, startname, state, processid, startmode, pathname, description

    As a side note, the pathname are quite useful for identifying malicious services
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STSoft

SYNOPSIS
    Gets installed software


SYNTAX
    Get-STSoft [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets installed software from a remote machine via remoting. Remoting must be working and you
    must have appropriate persissions for this to function properly.

    Displays: DisplayName, DisplayVersion, Publisher, URLInfoAbout, InstallDate, and InstallLocation
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STSysInfo

SYNOPSIS
    Gets basic system information


SYNTAX
    Get-STSysInfo [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets basic system information from a remote machine including: Hardware details, OS details, Time Zone, IE & Java versions, Net Adapters, and Disks (physical, usb, and mapped).

    This returns a text blob and not a custom PS Object like the other Get-ST functions
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STUserProf

SYNOPSIS
    Gets user profiles


SYNTAX
    Get-STUserProf [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets user profiles and other related information from a remote machine. The 'serv_path field
    is the remote profile path if there is one and the 'dt_time' is the last time that profile
    was accessed.

    Displays: sid, localpath, servpath, user
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


NAME
    Get-STUserSess

SYNOPSIS
    Gets user logon sessions


SYNTAX
    Get-STUserSess [-target] <String> [<CommonParameters>]


DESCRIPTION
    Gets user logon sessions and other related information from a remote machine. The data
    returned consists of all logon sessions and doe not distinguish between stale and active

    Displays: LogonType, LogonID, LogonName, StartTime
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

NAME
    Get-STDataDump

SYNOPSIS
    Runs all of the SysTools functions


SYNTAX
    Get-STDataDump [-target] <String> [[-outdir] <String>] [[-fulldump] <Boolean>] [<CommonParameters>]


DESCRIPTION
    Executes all of the SysTools functions against a remote machine and optionally exports the data to the specified directory. The return value is a Hash object that contains the results of each fun
    ction. Note the info below is assuming you are running it and putting the results in $data variable. It could be any variable, just note it doesn't have to be $data. For example $data = Get-STDat
    aDump -target "MyTest" -outdir "C:\datacapture" -fulldump $true would return the following:
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

    