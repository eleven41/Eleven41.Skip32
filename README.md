# Eleven41.Skip32

Copyright (C) 2013, Eleven41 Software

Skip32 C# implementation.
32-bit block cipher based on Skipjack.

Adaptation of the skip32 C implementation:
http://www.qualcomm.com.au/PublicationsDocs/skip32.c

Heavily influenced by the php adaptation:
https://github.com/nlenepveu/Skip32

## Get It on NuGet!

	Install-Package Eleven41.Skip32

## LICENSE
[MIT License](https://github.com/eleven41/Eleven41.Skip32/blob/master/LICENSE.md)

## REQUIREMENTS

* Visual Studio 2012

## Sample Code

	Eleven41.Skip32.Skip32Cipher skip32 = new Eleven41.Skip32.Skip32Cipher(myKey);
	int encrypted42 = skip32.Encrypt(42);
	int plain42 = skip32.Decrypt(encrypted42);
	System.Diagnostic.Debug.Assert(plain42 == 42);
	
