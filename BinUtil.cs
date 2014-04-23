/// Copyright (C) 2012 SASAKI Takahiro All Rights Reserved ///
using System;
using System.Runtime.InteropServices;

class BinUtil
{
	static public byte[] Ascii2Byte(string strASCII)
	{
		return System.Text.Encoding.ASCII.GetBytes(strASCII);
	}
	static public byte[] UTF82Byte(string strASCII)
	{
		return System.Text.Encoding.UTF8.GetBytes(strASCII);
	}
	static public byte[] SJIS2Byte(string strASCII)
	{
		return System.Text.Encoding.GetEncoding("Shift_JIS").GetBytes(strASCII);
	}

	static public byte[] EncodeString(String str, ref byte[] bytes)
	{
		byte[] bytesStr = System.Text.Encoding.ASCII.GetBytes(str);
		Array.Copy( bytesStr, 0, bytes, 0, bytesStr.Length);
		return bytes;
	}

	static public bool BigEndian = true;
	static public ulong Encode(ulong t)
	{
		if (BigEndian)
		{
			t = (ulong)System.Net.IPAddress.HostToNetworkOrder( (Int64)t );
		}
		return t;
	}
	static public long Encode(long t)
	{
		if (BigEndian)
		{
			t = (long)System.Net.IPAddress.HostToNetworkOrder( (Int64)t );
		}
		return t;
	}
	static public uint Encode(uint t)
	{
		if (BigEndian)
		{
			t = (uint)System.Net.IPAddress.HostToNetworkOrder( (Int32)t );
		}
		return t;
	}
	static public int Encode(int t)
	{
		if (BigEndian)
		{
			t = (int)System.Net.IPAddress.HostToNetworkOrder( (Int32)t );
		}
		return t;
	}
	static public ushort Encode(ushort t)
	{
		if (BigEndian)
		{
			t = (ushort)System.Net.IPAddress.HostToNetworkOrder( (Int16)t );
		}
		return t;
	}
	static public short Encode(short t)
	{
		if (BigEndian)
		{
			t = (short)System.Net.IPAddress.HostToNetworkOrder( (Int16)t );
		}
		return t;
	}
		
	static public byte[] Structure2Bytes<Type>(Type t)
		where Type : struct
	{
		byte[] bytes = null;
		
		IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(t) );
		try {
		  Marshal.StructureToPtr( t, ptr, false);
		  bytes = new byte[Marshal.SizeOf(t) ];
		  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(t));
		} finally {
		  Marshal.FreeHGlobal(ptr);
		}
		return bytes;
	}

	static public Type Bytes2Structure<Type>(byte[] bytes)
		where Type : struct
	{
		int size;
		Type t =  default(Type); // default(Type)は、値型の場合 0, 参照型の場合 NULL
		size = bytes.Length;
		if ( Marshal.SizeOf(t) < bytes.Length ) size = Marshal.SizeOf(t);
		IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(t) );
		try {
//		  Marshal.StructureToPtr( t, ptr, false);
		  Marshal.Copy(bytes, 0, ptr, size);
		  t = (Type)Marshal.PtrToStructure(ptr, typeof(Type));
		} finally {
		  Marshal.FreeHGlobal(ptr);
		}
		return t;
	}

    // 16進数表記の文字列をバイト列に変換 
	static public byte[] HexStringToBytes(String byteString, ref byte[] bytes)
    {
        byte[] newBytes = new byte[bytes.Length];

        // 文字列の文字数(半角)が奇数の場合、頭に「0」を付ける 
        int length = byteString.Length;
        if (length % 2 == 1)
        {
            byteString = "0" + byteString;
            length++;
        }

        for (int i = 0; i < length - 1; i = i + 2)
        {
            // 16進数表記の文字列かどうかをチェック
            string buf = byteString.Substring(i, 2);
            if (System.Text.RegularExpressions.Regex.IsMatch(buf, @"^[0-9a-fA-F]{2}$"))
            {
                bytes.SetValue(Convert.ToByte(buf, 16), i / 2);
            }
            // // 16進数表記で無ければ「00」とする 
            else
            {
                bytes.SetValue(Convert.ToByte("00", 16), i / 2);
            }
        }

        return bytes;
    } 

	static public Object EncodeObject(Object obj)
	{
		Object retObj = obj;
		switch ( Type.GetTypeCode( obj.GetType() ) ) 
		{
		case TypeCode.UInt64:
			retObj = Encode( (ulong)obj );
			break;
		case TypeCode.Int64:
			retObj = Encode( (long)obj );
			break;
		case TypeCode.UInt32:
			retObj = Encode( (uint)obj );
			break;
		case TypeCode.Int32:
			retObj = Encode( (int)obj );
			break;
		case TypeCode.UInt16:
			retObj = Encode( (ushort)obj );
			break;
		case TypeCode.Int16:
			retObj = Encode( (short)obj );
			break;
		case TypeCode.Byte:
		case TypeCode.Char:
			break;
		default:
			break;
		}
		return retObj;
	}

	static public void EncodeFields(System.Reflection.FieldInfo f, ref Object obj)
	{
//		Console.WriteLine(" EncodeFileds {0} {1} {2}",f,f.FieldType,Type.GetTypeCode( f.FieldType ));
		switch ( Type.GetTypeCode( f.FieldType ) ) 
		{
		case TypeCode.UInt64:
		case TypeCode.Int64:
		case TypeCode.UInt32:
		case TypeCode.Int32:
		case TypeCode.UInt16:
		case TypeCode.Int16:
			f.SetValue( obj, EncodeObject( f.GetValue(obj) )) ;
			break;
		case TypeCode.Byte:
		case TypeCode.Char:
			break;
		default:
//			Console.WriteLine(">>");
			if ( f.FieldType.IsArray )
			{
				Array a = (Array)f.GetValue(obj);
				for( int i=0 ; i<a.Length; ++i )
				{	
					a.SetValue(EncodeObject(a.GetValue(i)),i);
				}
				f.SetValue( obj, a);
				break;
			}
			foreach(System.Reflection.FieldInfo ff in f.FieldType.GetFields())
			{
				object fObj = f.GetValue(obj);
				EncodeFields(ff, ref fObj );
				f.SetValue( obj, fObj);
			}
//			Console.WriteLine("<<");
			break;
		}
		return;
	}
	static public T Encode<T>(T t)
		where T : struct
	{
		Object obj = (Object)t;
		foreach(System.Reflection.FieldInfo f in t.GetType().GetFields())
		{
			EncodeFields(f, ref obj);
		}
		return (T)obj;
	}
}



//------------------------------------------------------------------------------
#if UTEST
[StructLayout(LayoutKind.Sequential)]
public struct ethernet_hdstr {
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
  public byte[] dst;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
  public byte[] src;
  public short type;
}

[StructLayout(LayoutKind.Sequential, Pack=1)]
public struct str_hoge_child {
  public ushort c_us;
  public uint c_ui;
  public byte c_b;
}

[StructLayout(LayoutKind.Sequential, Pack=1)]
public struct str_hoge {
  public ushort us;
  public uint ui;
  public byte b;
  public str_hoge_child child;
}
class BinUtil_UTest
{
	static public void Main()
	{
		try {
			byte[] bytes;
			ethernet_hdstr ethernet_header;
			ethernet_header.dst = new byte[] {1,2,3,4,5,6};
			ethernet_header.src = new byte[] {0xa,0xb,0xc,0xd,0xe,0xf};
			ethernet_header.type = System.Net.IPAddress.HostToNetworkOrder( (short) 0x0800 );
			
			Console.WriteLine(" --- Ether Header ---");
			bytes = BinUtil.Structure2Bytes(ethernet_header);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );

			Console.WriteLine(" --- Ether Header(Swap) ---");
			ethernet_header = BinUtil.Encode<ethernet_hdstr>(ethernet_header);
			bytes = BinUtil.Structure2Bytes(ethernet_header);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );

			bytes = BinUtil.Ascii2Byte("ABCabc012 !#$%&'()=~\\|-^@`[]:;_/.,");
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			
			bytes = BinUtil.Ascii2Byte( Environment.NewLine );
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			
			bytes = BinUtil.Ascii2Byte( "あ①ABC" );
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );

			bytes = BinUtil.UTF82Byte( "あ①ABC" );
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			
			bytes = BinUtil.SJIS2Byte( "あ①ABC" );
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );

			str_hoge hoge;
			Console.WriteLine(" --- bytes 7byte ---");
			bytes = new byte[] { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef};
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			hoge = BinUtil.Bytes2Structure<str_hoge>(bytes);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);
			Console.WriteLine("  Encode Swap HOGE");
			hoge = BinUtil.Encode<str_hoge>(hoge);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);

			bytes = BinUtil.Structure2Bytes(hoge);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );

			Console.WriteLine(" --- bytes 3byte ---");
			bytes = new byte[] { 0x12,0x34,0x56};
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			hoge = BinUtil.Bytes2Structure<str_hoge>(bytes);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2}",hoge.us, hoge.ui, hoge.b);
			bytes = BinUtil.Structure2Bytes(hoge);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			
			Console.WriteLine(" --- bytes 18byte ---");
			bytes = new byte[] { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef,0xFF,0xFE,0x01,0x23,0x45,0x67,0x89,0xFF,0xFF,0xDE,0xAD};
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			hoge = BinUtil.Bytes2Structure<str_hoge>(bytes);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);
			Console.WriteLine("  Encode Swap HOGE");
			hoge = BinUtil.Encode<str_hoge>(hoge);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);
			Console.WriteLine("  Encode Swap HOGE");
			hoge = BinUtil.Encode<str_hoge>(hoge);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);
			bytes = BinUtil.Structure2Bytes(hoge);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			

			Console.WriteLine(" --- bytes 0byte ---");
			bytes = new byte[] {};
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			hoge = BinUtil.Bytes2Structure<str_hoge>(bytes);
			Console.WriteLine( "HOGE {0:X4},{1:X8},{2} (HOGE_CHILD {3:X4},{4:X8},{5})",hoge.us, hoge.ui, hoge.b, hoge.child.c_us, hoge.child.c_ui, hoge.child.c_b);
			bytes = BinUtil.Structure2Bytes(hoge);
			Console.WriteLine( DumpLib.BytesToHexStrZ( bytes , Environment.NewLine) );
			
			bytes = new byte[] { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
			for(int i=0;i<100;i++)
			{
				byte[] b;
				for(int j=0;j<10000;j++)
				{
					hoge = BinUtil.Bytes2Structure<str_hoge>(bytes);
					b = BinUtil.Structure2Bytes(hoge);
				}
				System.Threading.Thread.Sleep(10);
			}

			Console.WriteLine("### Program Finished.");
			Console.ReadLine();	
		}
		catch (Exception exp)
		{
			Console.WriteLine("{0}",exp.ToString());
			Console.WriteLine("### Program Finished.");
			Console.ReadLine();	
		}
	}
}
#endif // UTEST
//------------------------------------------------------------------------------

