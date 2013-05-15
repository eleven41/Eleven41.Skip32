using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
	class Program
	{
		static void Main(string[] args)
		{
			Eleven41.Skip32.Skip32Cipher cipher = new Eleven41.Skip32.Skip32Cipher("1234567890abcdef0123", Eleven41.Skip32.Skip32CipherKeyFormat.HexString);

			for (int i = 0; i < int.MaxValue; ++i)
			{
				// Encrypt, then reverse the encryption
				var value0 = i;
				var value1 = cipher.Encrypt(value0);
				var value2 = cipher.Decrypt(value1);
				
				// Display progress
				//Console.WriteLine("{0} -> {1} -> {2}", value0, value1, value2);
				if (i % 1000000 == 0)
					Console.WriteLine("{0}", i);

				// Ensure that the encryption is reversible
				System.Diagnostics.Debug.Assert(value0 == value2);

				// Ensure the encryption is not an identity function
				System.Diagnostics.Debug.Assert(value0 != value1);
			}
		}
	}
}
