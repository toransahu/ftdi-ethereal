http://developer.covenanteyes.com/building-openssl-for-visual-studio/
https://stackoverflow.com/questions/11383942/how-to-use-openssl-with-visual-studio

- project flow
	- http://www.technical-recipes.com/2014/using-openssl-sha-256-in-visual-c/

- lib conf
	- https://stackoverflow.com/questions/32156336/how-to-include-openssl-in-visual-studio-expres-2012-windows-7-x64
- openssl built exe
	- https://slproweb.com/products/Win32OpenSSL.html
		- download  	30MB Installer	

- openssl setup
	- download 		
		- https://slproweb.com/products/Win32OpenSSL.html
		- download  	30MB Installer	
	- follow (except dll thing)
		- https://stackoverflow.com/questions/32156336/how-to-include-openssl-in-visual-studio-expres-2012-windows-7-x64
	- include <openssl/evp.h>
	-  if needed
		- in stdafx.h
			```c
			// additional
			#include <iostream>
			#include <string>


			#include <math.h>
			#include <tchar.h>
			#include <Windows.h>
			```
	- evp eg
		- https://github.com/saju/misc/blob/master/misc/openssl_aes.c
		- https://medium.com/@amit.kulkarni/encrypting-decrypting-a-file-using-openssl-evp-b26e0e4d28d4
		- https://stackoverflow.com/questions/24856303/openssl-aes-256-cbc-via-evp-api-in-c
	- project conf : ignore fopen warning()
		- https://stackoverflow.com/questions/21873048/getting-an-error-fopen-this-function-or-variable-may-be-unsafe-when-complin


	- simple-crypto
		- add libcrypto.lib to linker