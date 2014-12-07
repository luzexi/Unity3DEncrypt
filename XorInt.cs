using System;


//xor int
public class XorInt
{
	int key;
	
	public XorInt() : this(0)
	{
	}
	
	public XorInt(int value)
	{
		GenerateKey();
		rawValue = Xor(value);
	}
	
	void GenerateKey()
	{
		var buffer = new byte[sizeof(int)];
		new Random().NextBytes(buffer);
		key = BitConverter.ToInt32(buffer, 0);
	}
	
	public int rawValue { get; private set; }
	
	public int value
	{
		get { return Xor(rawValue); }
		set { rawValue = Xor(value); }
	}
	
	int Xor(int x)
	{
		return x ^ key;
	}
	
	public static implicit operator int(XorInt xor)
	{
		if (xor == null)
		{
			return 0;
		}
		return xor.value;
	}
	
	public static implicit operator XorInt(int val)
	{
		return new XorInt(val);
	}

	public static XorInt operator++ (XorInt val)
	{
		val = val + 1;

		return val;
	}

	public static XorInt operator-- (XorInt val)
	{
		val = val - 1;

		return val;
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