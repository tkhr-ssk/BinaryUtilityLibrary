/// Copyright (C) 2012 SASAKI Takahiro All Rights Reserved ///
using System;
using System.Text;

class DumpLib
{
	//
	// データ取得（ビッグエンディアン）
	//
	static public byte GetByte(byte[] b,ref int pos)
	{
		return b[pos++];
	}
	
	static public ushort Get2Byte(byte[] b,ref int pos)
	{
		ushort us;
		us = (ushort)((int)b[pos++]<<8);
		us += b[pos++];
		return  us;
	}
	static public ulong Get4Byte(byte[] b,ref int pos)
	{
		ulong ul;
		ul = (ulong)((int)b[pos++]<<24);
		ul += (ulong)((int)b[pos++]<<16);
		ul += (ulong)((int)b[pos++]<<8);
		ul += b[pos++];
		return  ul;
	}
	
	//
	// データ取得（リトルエンディアン）
	//
	static public ushort Get2ByteLE(byte[] b,ref int pos)
	{
		ushort us;
		us  = (ushort)(b[pos++]);
		us += (ushort)((int)b[pos++]<<8);
		return  us;
	}
	static public ulong Get4ByteLE(byte[] b,ref int pos)
	{
		ulong ul;
		ul  = b[pos++];
		ul += (ulong)((int)b[pos++]<<8);
		ul += (ulong)((int)b[pos++]<<16);
		ul += (ulong)((int)b[pos++]<<24);
		return  ul;
	}
	
	//
	// データダンプ（ビッグエンディアン）
	//
	static string DumpByte(byte[] b,ref int pos, int size)
	{
		StringBuilder strb = new StringBuilder();
		for(int i=0; i<size;i++)
		{
			if( b.Length < pos)
			{
				break;
			}
			strb.Append( b[pos++].ToString("X2") );
		}
		return strb.ToString();
	}
	
	static string Dump2Byte(byte[] b,ref int pos, int size)
	{
		StringBuilder strb = new StringBuilder();
		for(int i=0; i<size;i++)
		{
			if( b.Length < pos)
			{
				break;
			}
			if( (i != 0) && ((i%2) == 0) ){
				strb.Append(" ");
			}
			strb.Append( b[pos++].ToString("X2") );
		}
		return strb.ToString();
	}
	
	static string Dump4Byte(byte[] b,ref int pos, int size)
	{
		StringBuilder strb = new StringBuilder();
		for(int i=0; i<size;i++)
		{
			if( b.Length < pos)
			{
				break;
			}
			if( (i != 0) && ((i%4) == 0) ){
				strb.Append(" ");
			}
			strb.Append( b[pos++].ToString("X2") );
		}
		return strb.ToString();
	}

	static public string BytesToStr(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder();
		foreach(byte b in bytes)
		{
			if(b < 0x20 || 0x7e < b){
				sb.Append(".");
				continue;
			}
			sb.Append( new ASCIIEncoding().GetString( new byte[] {b} ) );
		}
		return sb.ToString();
	}

	static public string BytesToStr(byte[] bytes, char c)
	{
		StringBuilder sb = new StringBuilder();
		foreach(byte b in bytes)
		{
			if( b == 0x2c){ sb.Append('_') ; continue; }
			if(b < 0x20 || 0x7e < b){
				sb.Append(c);
				continue;
			}
			sb.Append( new ASCIIEncoding().GetString( new byte[] {b} ) );
		}
		return sb.ToString();
	}

	static public string BytesToStrAscii(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder();
		foreach(byte b in bytes)
		{
			if(b < 0x20 || 0x7e < b){
				break;
			}
			sb.Append( new ASCIIEncoding().GetString( new byte[] {b} ) );
		}
		return sb.ToString();
	}

	static public string BytesToAscii(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder();
		foreach(byte b in bytes)
		{
			if(b < 0x20 || 0x7e < b){
				sb.Append(".");
				continue;
			}
			sb.Append( new ASCIIEncoding().GetString( new byte[] {b} ) );
		}
		return sb.ToString();
	}

	static public string BytesToHexStr(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder();
//		sb.Append("0x");
		foreach(byte b in bytes)
		{
			sb.Append( String.Format("{0:X2}" ,b) );
		}
		return sb.ToString();
	}
	
	static public string BytesToHexStr2(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder();
//		sb.Append("0x");
		int i=0;
		foreach(byte b in bytes)
		{
			sb.Append( String.Format("{0:x2}" ,b) );
			if( 0 == ( (++i)%2 ) ) sb.Append(" ");
		}
		return sb.ToString();
	}

	
	static public string BytesToHexStr2(byte[] bytes, int div)
	{
		StringBuilder sb = new StringBuilder();
//		sb.Append("0x");
		int i=0;
		foreach(byte b in bytes)
		{
			sb.Append( String.Format("{0:X2}" ,b) );
			if( 0 == ( (++i)%div ) ) sb.Append(" ");
		}
		return sb.ToString();
	}

	static public string BytesToHexStr3(byte[] bytes, int div, int lineDiv)
	{
		StringBuilder sb = new StringBuilder();
//		sb.Append("0x");
		int i=0;
		foreach(byte b in bytes)
		{
			sb.Append( String.Format("{0:X2}" ,b) );
			if( 0 == ( (++i)%div ) ) sb.Append(" ");
			if( 0 == ( (i)%lineDiv ) ) sb.Append(Environment.NewLine);
		}
		return sb.ToString();
	}

	static public string BytesToHexStrZ(byte[] bytes)
	{
		string offsetString = Environment.NewLine + "  :  ";
		return BytesToHexStrZ(bytes, offsetString);
	}
	static public string BytesToHexStrZ(byte[] bytes, string offsetString)
	{
		StringBuilder sb = new StringBuilder();
//		sb.Append("0x");
		int i;
		int offset=0;
		byte[] tmpBytes;

		while(true)
		{
			tmpBytes = GetBytes(bytes, offset*16 ,16);
			if( tmpBytes.Length < 16 ) break;
			if( 0 != offset) sb.Append(offsetString);
			i=0;
			foreach(byte b in tmpBytes)
			{
				if( 0 == ( i%2 ) ) sb.Append(" ");
				sb.Append( String.Format("{0:x2}" ,b) );
				++i;
			}
			sb.Append(" : ");
			sb.Append( BytesToAscii( tmpBytes ) );
			offset++;
		}
		if( 0 < tmpBytes.Length )
		{
			if( 0 != offset) sb.Append(offsetString);
			i=0;
			foreach(byte b in tmpBytes)
			{
				if( 0 == ( i%2 ) ) sb.Append(" ");
				sb.Append( String.Format("{0:x2}" ,b) );
				++i;
			}
			for( ;i<16;++i){
				if( 0 == ( i%2 ) ) sb.Append(" ");
				sb.Append("  ");
			}
			sb.Append(" : ");
			sb.Append( BytesToAscii( tmpBytes ) );
		}
		
		return sb.ToString();
	}

	// for Big Endian
	static public int BytesToInt(byte[] bytes)
	{
		int num = 0;
		foreach(byte b in bytes)
		{
			num = (num << 8) + b;
		}
		return num;
	}

	static public uint BytesToUInt(byte[] bytes)
	{
		uint num = 0;
		foreach(byte b in bytes)
		{
			num = (num << 8) + b;
		}
		return num;
	}

	// for Little Endian
	static ulong BytesToIntLE(byte[] bytes)
	{
		ulong num = 0;
		int i=0;
		foreach(byte b in bytes)
		{
			num += (ulong)(b<<(8*i));
			i++;
		}
		return num;
	}

	static public byte[]  GetBytes(byte[] bytes, int offset, int size)
	{
		byte[] ret_bytes;
		if(bytes.Length < offset+size )
		{
			size = bytes.Length - offset;
		}
		
		ret_bytes = new byte[size];
		Array.Copy(bytes, offset, ret_bytes, 0, size);
		return ret_bytes;
	}

	static public byte[] BytesCombine(byte[] bytesA, byte[] bytesB )
	{
		byte[] ret_bytes;
		int size;
		size = bytesA.Length + bytesB.Length;

		ret_bytes = new byte[size];

		Array.Copy( bytesA, 0, ret_bytes, 0, bytesA.Length );
		Array.Copy( bytesB, 0, ret_bytes, bytesA.Length, bytesB.Length );
		
		return ret_bytes;
	}


	// 文字列をバイト列に変換
	static public byte[] Str2Bytes(string str)
	{
		byte[]	bytes;
		int len;
		len = str.Length/2;
		if( 0 != str.Length%2 )
		{
			len++;
		}

		bytes = new byte[len];
		int pos = 0;
		while(str.Length >= 2)
		{
			bytes[pos] = (byte)Convert.ToInt32(str.Substring(0,2), 16);
			str = str.Substring(2);
			pos++;
		}
		if(str.Length == 1)
		{
			bytes[pos] = (byte)(Convert.ToInt32(str.Substring(0,1), 16)<<4);
			pos++;
		}
		if( pos < len )
		{
			bytes = GetBytes(bytes,0,pos);
		}
		return bytes;
	}

	static public uint Str2UInt32(string str)
	{
		string s = str.Trim();
		uint val = 0;
		if( s.Length > 2 && s.Substring(0,2) == "0x" )
		{
			val = Convert.ToUInt32(s.Substring(2),16);
		}
		else
		{
			val =uint.Parse( s );
		}
		return val;
	}

	static public ushort Str2UInt16(string str)
	{
		string s = str.Trim();
		ushort val = 0;
		if( s.Length > 2 && s.Substring(0,2) == "0x" )
		{
			val = Convert.ToUInt16(s.Substring(2),16);
		}
		else
		{
			val =ushort.Parse( s );
		}
		return val;
	}

	public static int IntParse(string _s)
	{
		string s = _s.Trim();
		int val =0;
		try{
			if( s.Length > 2 && s.Substring(0,2) == "0x" )
			{
				val = Convert.ToInt32(s.Substring(2),16);
			}
			else
			{
				val =int.Parse( s );
			}
		}
		catch(Exception e)
		{
			Console.WriteLine(e);
			Console.WriteLine("IntParse <- "+_s);
		}
		return val;
	}

	public static string ByteSubstring(
			string str,
			int idx,
			int len)
	{
		string ret = "";
		int start = 0;
		Encoding sjis = Encoding.GetEncoding("Shift_JIS");
		int i=0;
		if(idx<0)idx=0;

//			Console.WriteLine("call:{0},{1},{2}",str,idx,len);
		
		if(0 == idx )
		{
			start = 0;
		}else{
			int byteCnt = 0;
			for(i=0;i<str.Length-1;i++)
			{
				string tmp = str.Substring(i,1);
				byteCnt += sjis.GetByteCount(tmp);
				if(byteCnt >= idx)
				{
					start = i+1;
					break;
				}
			}
//				Console.WriteLine( "byteCnt:{0} start:{1}",byteCnt,start);
		}
		for(i=0;i<str.Length-1;i++)
		{
			if(i>=start)
			{
				string tmp = str.Substring(i,1);
				if(sjis.GetByteCount(ret + tmp) <= len)
				{
					ret += tmp;
				}
			}
		}
//			Console.WriteLine( "ret:[{0}]",ret);
		return ret;
	}
}
