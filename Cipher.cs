using UnityEngine;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;



//cipher
public class Cipher
{

	public static string DEFAULT_NETWORKHASH;
	public static string DEFAULT_IV_128;

	private const string KEY_FACTORY_ALGORITHM = "RSA";
	private const string SIGNATURE_ALGORITHM = "Sha256WithRSA";

	// same signature/wcat_public.pem
	private const string PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAytwW/1jarl9pOzhWLYn4rLO5TQAY3FLj/smhQRqyQTU2Kn8+Xqg6d5+392dlFziZUFhBivmAJKuf+i5nyE3bxfsgXwN5auea1sanDO0AsKT62Cqb9aUzYObOhkcObK2QHsW2WP7e9pQvrg+J+DVvr+JXwH60xsjFSSte5gq+zCKtlhceSEZ6OTghufGgNGtASODKsVtiu/iFvCkH6bVJ3JYXsfSsy7Oj1/Ov7cbrCgUM49Qhv0r68DvpAiBSSr715gkWcZcWoJ54ZKWWsaBvrIA2Y+qHP8FwqPX8m5Uh0dbh8fznXprjdbtQUPPPR6z6TIc+ESI4K/D/AyJigtsuOwIDAQAB";

	static Cipher()
	{
		DEFAULT_NETWORKHASH = "Y.u=M,N-!8Jd2`RXE)k!]y<w2TFg-[4Z";
		DEFAULT_IV_128 = "=q$f]p&(K.3_#hHk";
	}

	public static string EncryptRJ128(string prm_key, string prm_iv, string prm_text_to_encrypt)
	{
		return EncryptRJ128Byte(prm_key, prm_iv, Encoding.UTF8.GetBytes(prm_text_to_encrypt));
	}

	public static string EncryptRJ128Byte(string prm_key, string prm_iv, byte[] toEncrypt)
	{

		var myRijndael = new RijndaelManaged() {
			Padding = PaddingMode.PKCS7,
			Mode = CipherMode.CBC,
			KeySize = 256,
			BlockSize = 128
		};

		var key = Encoding.UTF8.GetBytes(prm_key);
		var IV = Encoding.UTF8.GetBytes(prm_iv);

		var encryptor = myRijndael.CreateEncryptor(key, IV);
		var msEncrypt = new MemoryStream();
		var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

		csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
		csEncrypt.FlushFinalBlock();

		var encrypted = msEncrypt.ToArray();

		return (Convert.ToBase64String(encrypted));
	}

	public static string DecryptRJ128(string prm_key, string prm_iv, string prm_text_to_decrypt)
	{
		byte[] decrypt = DecryptRJ128Byte(prm_key, prm_iv, prm_text_to_decrypt);
		if( decrypt == null ){
			return null;
		}
		var decryptStr = Encoding.UTF8.GetString(decrypt);
		return decryptStr;
	}

	public static byte[] DecryptRJ128Byte(string prm_key, string prm_iv, string prm_text_to_decrypt)
	{
		var sEncryptedString = prm_text_to_decrypt;

		var myRijndael = new RijndaelManaged() {
			Padding = PaddingMode.PKCS7,
			Mode = CipherMode.CBC,
			KeySize = 256,
			BlockSize = 128
		};

		var key = Encoding.UTF8.GetBytes(prm_key);
		var IV = Encoding.UTF8.GetBytes(prm_iv);

		var decryptor = myRijndael.CreateDecryptor(key, IV);
		var sEncrypted = Convert.FromBase64String(sEncryptedString);
		var fromEncrypt = new byte[sEncrypted.Length];
		var msDecrypt = new MemoryStream(sEncrypted);
		var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

		int numOfChars = csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);
		Array.Resize (ref fromEncrypt, numOfChars);

		return fromEncrypt;
	}

	public static bool verify(string signedData, string base64Signature)
	{
		// raw signature data
		byte[] signature  = Convert.FromBase64String(base64Signature);

		// Generate RSACryptoServiceProvider from public key.
		byte[] publicKeyBytes = Convert.FromBase64String(PUBLIC_KEY_STRING);
		RSACryptoServiceProvider RSA = DecodeX509PublicKey(publicKeyBytes);

		//
		RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
		RSADeformatter.SetHashAlgorithm("SHA256");

		// compute sha256 hash of passed data
		byte[] generatedHash = SHA256Hash(signedData);

		bool result = false;
		if(RSADeformatter.VerifySignature(generatedHash, signature))
		{
			result = true;
		}
		return result;
	}

	public static byte[] SHA256Hash(string text)
	{
		byte[] byteArray = Encoding.UTF8.GetBytes(text);
		byte[] hash = null;
		try
		{
			SHA256 myShA256 = SHA256Managed.Create();
			hash = myShA256.ComputeHash(byteArray);
		}
		catch (Exception)
		{
			Debug.Log("SHA256.ComputHash failed");
			return null;
		}
		return hash;
	}

	// ref. http://stackoverflow.com/questions/11506891/how-to-load-the-rsa-public-key-from-file-in-c-sharp
	private static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
	{
		// encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
		byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
		byte[] seq = new byte[15];
		// ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
		MemoryStream mem = new MemoryStream(x509key);
		BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
		byte bt = 0;
		ushort twobytes = 0;

		try
		{

			twobytes = binr.ReadUInt16();
			if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
				binr.ReadByte();    //advance 1 byte
			else if (twobytes == 0x8230)
				binr.ReadInt16();   //advance 2 bytes
			else
				return null;

			seq = binr.ReadBytes(15);       //read the Sequence OID
			if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
				return null;

			twobytes = binr.ReadUInt16();
			if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
				binr.ReadByte();    //advance 1 byte
			else if (twobytes == 0x8203)
				binr.ReadInt16();   //advance 2 bytes
			else
				return null;

			bt = binr.ReadByte();
			if (bt != 0x00)     //expect null byte next
				return null;

			twobytes = binr.ReadUInt16();
			if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
				binr.ReadByte();    //advance 1 byte
			else if (twobytes == 0x8230)
				binr.ReadInt16();   //advance 2 bytes
			else
				return null;

			twobytes = binr.ReadUInt16();
			byte lowbyte = 0x00;
			byte highbyte = 0x00;

			if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
				lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
			else if (twobytes == 0x8202)
			{
				highbyte = binr.ReadByte(); //advance 2 bytes
				lowbyte = binr.ReadByte();
			}
			else
				return null;
			byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
			int modsize = BitConverter.ToInt32(modint, 0);

			byte firstbyte = binr.ReadByte();
			binr.BaseStream.Seek(-1, SeekOrigin.Current);

			if (firstbyte == 0x00)
			{   //if first byte (highest order) of modulus is zero, don't include it
				binr.ReadByte();    //skip this null byte
				modsize -= 1;   //reduce modulus buffer size by 1
			}

			byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

			if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
				return null;
			int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
			byte[] exponent = binr.ReadBytes(expbytes);

			// ------- create RSACryptoServiceProvider instance and initialize with public key -----
			RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
			RSAParameters RSAKeyInfo = new RSAParameters();
			RSAKeyInfo.Modulus = modulus;
			RSAKeyInfo.Exponent = exponent;
			RSA.ImportParameters(RSAKeyInfo);
			return RSA;
		}
		catch (Exception)
		{
			return null;
		}

		finally { binr.Close(); }

	}

	private static bool CompareBytearrays(byte[] a, byte[] b)
	{
		if (a.Length != b.Length)
			return false;
		int i = 0;
		foreach (byte c in a)
		{
			if (c != b[i])
				return false;
			i++;
		}
		return true;
	}
}
