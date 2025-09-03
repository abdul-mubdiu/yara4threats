rule urhan {
	meta:
	  description = "Rule for urhan.exe"
	  author = "Mubdiu Aro-lambo"
	strings:
	  $s1 = "ReleaseActCtx" ascii wide
	  $s2 = "OpenSemaphoreA"
	  $s3 = "CreateMailslotW"
	  $s4 = "HeapWalk"
	  $Hex = {ddf3 af12 e8fb b40d d5f7 a60a}
	condition:
	  all of them
	  }
