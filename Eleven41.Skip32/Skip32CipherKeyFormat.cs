using System;

namespace Eleven41.Skip32
{
	public enum Skip32CipherKeyFormat
	{
		Base64,

		/// <summary>
		/// String representation of bytes encoded as hexadecimal characters. 2 characters per byte.
		/// </summary>
		HexString
	}
}
