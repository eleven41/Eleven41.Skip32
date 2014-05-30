using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Eleven41.Skip32.UnitTests
{
	[TestClass]
	public class Skip32CipherTests
	{
		// This test takes a few minutes to execute
		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void null_byte_array_key()
		{
			byte[] key = null;
			Skip32Cipher cipher = new Skip32Cipher(key);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentOutOfRangeException))]
		public void incorrect_byte_array_key_length()
		{
			byte[] key = new byte[1];
			Skip32Cipher cipher = new Skip32Cipher(key);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void null_hex_key()
		{
			string key = null;
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.HexString);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void null_base64_key()
		{
			string key = null;
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.Base64);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void empty_hex_key()
		{
			string key = "";
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.HexString);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void empty_base64_key()
		{
			string key = "";
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.Base64);
		}

		[ExpectedException(typeof(ArgumentOutOfRangeException))]
		public void incorrect_hex_key_length()
		{
			string key = "abc";
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.HexString);
		}

		[ExpectedException(typeof(ArgumentOutOfRangeException))]
		public void incorrect_base64_key_length()
		{
			string key = "abcd";
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.Base64);
		}

		[ExpectedException(typeof(FormatException))]
		public void invalid_base64_key_length()
		{
			string key = "abcde";
			Skip32Cipher cipher = new Skip32Cipher(key, Skip32CipherKeyFormat.Base64);
		}

		// This test takes a few minutes to execute
		[TestMethod]
		public void test_0()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = 0;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.AreEqual(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.AreNotEqual(value0, value1);
		}

		[TestMethod]
		public void test_1()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = 0;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.AreEqual(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.AreNotEqual(value0, value1);
		}

		[TestMethod]
		public void test_random()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			Random r = new Random();
			int value0 = r.Next();
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.AreEqual(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.AreNotEqual(value0, value1);
		}

		[TestMethod]
		public void test_MinValue()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = int.MinValue;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.AreEqual(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.AreNotEqual(value0, value1);
		}

		[TestMethod]
		public void test_MaxValue()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = int.MaxValue;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.AreEqual(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.AreNotEqual(value0, value1);
		}
	}
}
