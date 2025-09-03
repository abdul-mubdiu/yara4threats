rule four {
	meta:
	  description = "Rule for 4.exe"
	  author = "Mubdiu Aro-lambo"
	strings:
	  $s1 = "vbase destructor"
	  $s2 = "FreeLibraryWhenCallbackReturns"
	  $s3 = "C:\\vixugosa58 cimoxegimovapa mek58\\pekazeja diwapon.pdb"
	  $hex = {e038 f438 f838 0839 0c39 1039}
	condition:
	  all of them
	}
