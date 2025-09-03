rule runlast {
	meta:
	  description = "Rule for run-last.exe"
	  author = "Mubdiu Aro-lambo"
	strings:
	  $1 = "CFI%Wr%LOG3^rU"
	  $s2 = "Y9999\\_bh9999kntwA"
	  $s3 = "U''''X[^d''''jm4p" ascii wide
	condition:
	 2 of them
	 }
