using UnityEngine;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;


// Wapper for PlayerPrefs
// Add crypto features to raw data
public class CryptoPrefs
{

	private static string sKEY = "ZTdkNTNmNDE2NTM3MWM0NDFhNTEzNzU1";
	private static string sIV  = "4rZymEMfa/PpeJ89qY4gyA==";

	// ==================================================================================
	//  PlayerPrefs wrapper methods.
	// key : will be hashed by md5.
	// val  : will be encripted with AES (Rijndeal_128).
	// ==================================================================================

	public static void SetInt( string key, int val ){
		PlayerPrefs.SetString( GetHash(key), Encrypt(val.ToString()) );
	}

	public static int GetInt( string key, int defaultValue = 0 ){
		string valStr = GetString( key, defaultValue.ToString() );
		int val = defaultValue;
		int.TryParse( valStr, out val );
		return val;
	}

	public static void SetFloat( string key, float val ){
		PlayerPrefs.SetString( GetHash(key), Encrypt(val.ToString()) );
	}

	public static float GetFloat( string key, float defaultValue = 0.0f ){
		string valStr = GetString( key, defaultValue.ToString() );
		float val = defaultValue;
		float.TryParse( valStr, out val );
		return val;
	}

	public static void SetString( string key, string val ){
		PlayerPrefs.SetString( GetHash(key), Encrypt(val) );
	}

	public static string GetString( string key, string defaultValue = "" ){
		string dec = defaultValue;
		string enc = PlayerPrefs.GetString( GetHash(key), defaultValue.ToString() );
		if( !dec.Equals(enc) ){
			dec = Decrypt( enc );
		}
		return dec;
	}

	public static bool HasKey( string key ){
		string hashedKey = GetHash( key );
		return PlayerPrefs.HasKey( hashedKey );
	}

	public static void DeleteKey( string key ){
		string hashedKey = GetHash( key );
		PlayerPrefs.DeleteKey( hashedKey );
	}

	public static void DeleteAll(){
		PlayerPrefs.DeleteAll();
	}

	public static void Save(){
		PlayerPrefs.Save();
	}

	// ==================================================================================
	// Local Encription / Decryption Utils
	// ==================================================================================
	private static string Decrypt(string encString) {
		var sEncryptedString = encString;

		var myRijndael = new RijndaelManaged() {
			Padding = PaddingMode.Zeros,
			Mode = CipherMode.CBC,
			KeySize = 128,
			BlockSize = 128
		};

		var key = Encoding.UTF8.GetBytes(sKEY);
		var IV  = Convert.FromBase64String(sIV);
		//Debug.Log( "IV:" + IV.Length + "  " + IV.ToString() );

		var decryptor   = myRijndael.CreateDecryptor(key, IV);
		var sEncrypted  = Convert.FromBase64String(sEncryptedString);
		var fromEncrypt = new byte[sEncrypted.Length];
		var msDecrypt   = new MemoryStream(sEncrypted);
		var csDecrypt   = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

		csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);

		return (Encoding.UTF8.GetString(fromEncrypt).TrimEnd('\0'));
	}

	private static string Encrypt(string rawString) {
		var sToEncrypt = rawString;

		var myRijndael = new RijndaelManaged() {
			Padding = PaddingMode.Zeros,
			Mode = CipherMode.CBC,
			KeySize = 128,
			BlockSize = 128
		};

		var key = Encoding.UTF8.GetBytes(sKEY);
		var IV  = Convert.FromBase64String(sIV);
		//Debug.Log( "IV:" + IV.Length + "  " + IV.ToString() );

		var encryptor = myRijndael.CreateEncryptor(key, IV);
		var msEncrypt = new MemoryStream();
		var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
		var toEncrypt = Encoding.UTF8.GetBytes(sToEncrypt);

		csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
		csEncrypt.FlushFinalBlock();

		var encrypted = msEncrypt.ToArray();

		return (Convert.ToBase64String(encrypted));
	}

	private static string GetHash( string key ){
		MD5 md5Hash = new MD5CryptoServiceProvider();
		byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(key));
		StringBuilder sBuilder = new StringBuilder();
		for (int i = 0; i < data.Length; i++) {
			sBuilder.Append(data[i].ToString("x2"));
		}
		return sBuilder.ToString();
	}

	// ==================================================================================
	// Unit Test
	// ==================================================================================
	/*
	public static void UnitTest(){
		string key1 = "TEST_KEY_001";
		string key2 = "TEST_KEY_002";
		string key3 = "TEST_KEY_003";
		string key4 = "TEST_KEY_004";

		Debug.Log( "[HASH] key1 : " + GetHash(key1) );
		Debug.Log( "[HASH] key2 : " + GetHash(key2) );
		Debug.Log( "[HASH] key3 : " + GetHash(key3) );
		Debug.Log( "[HASH] key4 : " + GetHash(key4) );

		CryptoPrefs.SetInt( key1, 12345 );
		int val1 = CryptoPrefs.GetInt( key1, 0 );
		Debug.Log( "[GET] " + key1 + "(" + GetHash(key1) + ")  -> " + val1);

		CryptoPrefs.SetFloat( key2, 3.141592f );
		float val2 = CryptoPrefs.GetFloat( key2, 0.1f );
		Debug.Log( "[GET] " + key2 + "(" + GetHash(key2) + ")  -> " + val2);

		CryptoPrefs.SetString( key3, "TESTSTR!!!!" );
		string val3 = CryptoPrefs.GetString( key3, "FAULT" );
		Debug.Log( "[GET] " + key3 + "(" + GetHash(key3) + ")  -> " + val3);

		CryptoPrefs.Save();

		Debug.Log( "[DEF] " + CryptoPrefs.GetInt( key4, -10 ) );
		Debug.Log( "[DEF] " + CryptoPrefs.GetFloat( key4, -1.732f ) );
		Debug.Log( "[DEF] " + CryptoPrefs.GetString( key4, "orz" ) );
		Debug.Log( "[DEF] " + CryptoPrefs.GetInt( key4 ) );
		Debug.Log( "[DEF] " + CryptoPrefs.GetFloat( key4 ) );
		Debug.Log( "[DEF] " + CryptoPrefs.GetString( key4 ) );

		Debug.Log( "[KEYS] " + CryptoPrefs.HasKey( key1 ) );
		Debug.Log( "[KEYS] " + CryptoPrefs.HasKey( key2 ) );
		Debug.Log( "[KEYS] " + CryptoPrefs.HasKey( key3 ) );
		Debug.Log( "[KEYS] " + CryptoPrefs.HasKey( key4 ) );

		// Encription Test
		int    raw1 = 1234567;
		float  raw2 = 1.41421356f;
		string raw3 = "orz=3";

		string enc1 = Encrypt( raw1.ToString() );
		string enc2 = Encrypt( raw2.ToString() );
		string enc3 = Encrypt( raw3.ToString() );

		Debug.Log( "[ENC] " + raw1 + "  ->  " + enc1 );
		Debug.Log( "[ENC] " + raw2 + "  ->  " + enc2 );
		Debug.Log( "[ENC] " + raw3 + "  ->  " + enc3 );
		Debug.Log( "[DEC] " + Decrypt( enc1 ) );
		Debug.Log( "[DEC] " + Decrypt( enc2 ) );
		Debug.Log( "[DEC] " + Decrypt( enc3 ) );
	}
	*/
}
