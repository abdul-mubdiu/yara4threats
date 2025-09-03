rule 19075NYPD {
	meta:
	  description = "Rule to detect 19075NYPD/CXYIJlo and other duplicates of the same payload usually using arbitrary names to self-duplicate"
	  author = "Mubdiu Aro-lambo"
	strings:
	  $path = "SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\"
	  $s1 = "InstallLanguage"
	  $s2 = "efkrm4tgkl4ytg4" ascii wide
	  $act1 = "FindFirstFileExW"
	  $act2 = "FindNextFileW"
	  $act3 = "ImpersonateSelf"
	  $dll1 = "ADVAPI32.dll"
	  $dll2 = "SHELL32.dll"
	  $dll3 = "WS2_32.dll"
	  $dll4 = "kernel32.dll"
	  $dll5 = "Iphlpapi.dll"
	  $Hex1 = {6f6c 6865 6c70 3332 536e 6170}
	  $Hex2 = {2e72 6461 7461 2473 7864 6174}
	condition:
	 2 of ($s*) and 2 of ($act*) and all of ($dll*) and $path and 1 of ($Hex*) 
	 }
