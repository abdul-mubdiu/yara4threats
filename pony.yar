rule pony {
	meta:
	  description = "Rule for pony.exe"
	  author = "Mubdiu Aro-lambo"
	strings:
	  $path1 = "C:\\jonimepekiyem.pdb"
	  $path2 = "ver\\runtime\\crypt\\tmp_233238447\\bin\\vaxel.pdb"
	  $s1 = "_ipst)8BLS(" ascii wide 
	condition:
	 all of them
	 }
