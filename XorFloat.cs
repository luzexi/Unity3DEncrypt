using System;


//xor float
public class XorFloat
{
	byte[] key = new byte[sizeof(float)];
	byte[] bytes = new byte[sizeof(float)];
	
	public XorFloat() : this(0f){}
	
	public XorFloat(float value)
	{
		GenerateKey();
		Xor(value);
	}
	
	void GenerateKey()
	{
		new Random().NextBytes(key);
	}
	
	public float value
	{
		get { return Xor(); }
		set { Xor(value); }
	}
	
	private void Xor(float x)
	{
		bytes = BitConverter.GetBytes(x);
		bytes[0] ^= key[0];
		bytes[1] ^= key[1];
		bytes[2] ^= key[2];
		bytes[3] ^= key[3];
	}

	private float Xor()
	{
		var val = new byte[sizeof(float)];
		val[0] = (byte)(bytes[0] ^ key[0]);
		val[1] = (byte)(bytes[1] ^ key[1]);
		val[2] = (byte)(bytes[2] ^ key[2]);
		val[3] = (byte)(bytes[3] ^ key[3]);
		
		return BitConverter.ToSingle(val, 0);
	}
	
	public static implicit operator float(XorFloat xor)
	{
		if (xor == null)
		{
			return 0f;
		}

		return xor.value;
	}
	
	public static implicit operator XorFloat(float val)
	{
		return new XorFloat(val);
	}

	public override string ToString()
	{
		return value.ToString();
	}
	
	public string ToString(string format)
	{
		return value.ToString(format);
	}

	public string ToString(IFormatProvider provider)
	{
		return value.ToString(provider);
	}

	public string ToString(string format, IFormatProvider provider)
	{
		return value.ToString(format, provider);
	}
}