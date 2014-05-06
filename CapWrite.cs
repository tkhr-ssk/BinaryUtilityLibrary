/// Copyright (C) 2012 SASAKI Takahiro All Rights Reserved ///
using System;
using System.IO;
using System.Text;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;

// 構造体⇒byte変換 
// http://gushwell.ldblog.jp/archives/50618358.html
//MyStruct o = new MyStruct();
//...
//IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(o));
//try {
//  Marshal.StructureToPtr(o, ptr, false);
//  byte[] bytes = new byte[Marshal.SizeOf(o)];
//  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(o));
//  ...
//} finally {
//  Marshal.FreeHGlobal(ptr);
//}
//

//int size = Marshal.SizeOf( structA );

//IPAddress.HostToNetworkOrder()

public class CapWrite {

  public bool UdpChecksumEnabled = true;

  protected pcap_pkthdr pcap_header;
  protected ethernet_hdstr ethernet_header;
  protected ip_hdstr ip_header;
  protected udp_hdstr udp_header;
  protected sctp_hdstr sctp_header;
//  tcp_hdstr tcp_header;

  private byte[] FILE_HEADER =
	{0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
  protected BinaryWriter bw = null;
  
  public CapWrite()
  {
	// 固定値の初期化
	pcap_header.tv_sec = 0;
	pcap_header.tv_usec = 0;
	ethernet_header.dst = new byte[] {0,0,0,0,0,0};
	ethernet_header.src = new byte[] {0,0,0,0,0,0};
	ethernet_header.type = IPAddress.HostToNetworkOrder( (short) 0x0800 );
	ip_header.version_length = 0x45;
	ip_header.differentiated_services_field = 0;
	ip_header.identification = 0;
	ip_header.flags = 0;
	ip_header.time_to_live = 128;
	ip_header.protocol = 17; // UDP
	ip_header.src = new byte[] { 0,1,2,3};
	ip_header.dst = new byte[] { 0,1,2,3};
	udp_header.checksum = 0;
  }

  public void Open(string FileName)
  {
	bw = new BinaryWriter(File.Open( FileName , FileMode.Create , FileAccess.Write) );
	// FileMode.Create : ファイルが存在する場合は Truncate ，ファイルが存在しない場合は CreateNew の要求と等価
	bw.Write( FILE_HEADER );
  }
  public void WriteFrameHeader(uint caplen, uint len)
  {
	WriteFrameHeader(caplen, len, 0, 0);
  }
  public void WriteFrameHeaderNow(uint caplen, uint len)
  {
	DateTime dtEpoch = new DateTime(1970, 1, 1);
	DateTime dtNow = DateTime.UtcNow;
	TimeSpan ts = dtNow - dtEpoch;
	WriteFrameHeader(caplen, len, (int)ts.TotalSeconds, dtNow.Millisecond * 1000);
  }
  public void WriteFrameHeader(uint caplen, uint len, int tv_sec, int tv_usec)
  {
	pcap_header.caplen = caplen;
	pcap_header.len = len;
	pcap_header.tv_sec = tv_sec;
	pcap_header.tv_usec = tv_usec;
	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(pcap_header) );
	try {
	  Marshal.StructureToPtr( pcap_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(pcap_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(pcap_header));
	  bw.Write( bytes );
//	  Console.WriteLine( "cap:{0} len:{1} bytes:{2}", caplen, len, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
  }

  public void WriteDummyEtherHeader()
  {
	WriteDummyEtherHeader(bw.BaseStream);
  }
  public void WriteDummyEtherHeader(Stream sr)
  {
	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(ethernet_header) );
	try {
	  Marshal.StructureToPtr( ethernet_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(ethernet_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(ethernet_header));
	  sr.Write( bytes ,0, bytes.Length);
//	  Console.WriteLine( "ether type:{0} len:{1}", ethernet_header.type, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
  }

  public void WriteIPHeader(byte[] src, byte[] dest, ushort data_len)
  {
	WriteIPHeader(src, dest, data_len, bw.BaseStream );
  }
  public void WriteIPHeader(byte[] src, byte[] dest, ushort data_len, Stream sr)
  {
	src.CopyTo( ip_header.src, 0);
	dest.CopyTo( ip_header.dst, 0);
	ip_header.total_length = (ushort)IPAddress.HostToNetworkOrder((short)( Marshal.SizeOf(ip_header) + data_len));
	// checksum
	// 16bitで1の補数の和を求め、求まった値の1の補数を格納
	// http://www.fenix.ne.jp/~thomas/memo/ip/checksum.html
	ulong sum = (ulong)( 0x4500 +  (Marshal.SizeOf(ip_header) + data_len) + 0x8000 + ip_header.protocol +
							 + (src[0]<<8)+src[1] + (src[2]<<8)+src[3]
							 + (dest[0]<<8)+dest[1] + (dest[2]<<8)+dest[3]);
	sum = (0xffff & sum) + (sum >> 16);
	sum = (0xffff & sum) + (sum >> 16);
	ip_header.checksum = IPAddress.HostToNetworkOrder((short)~sum);
	
	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(ip_header) );
	try {
	  Marshal.StructureToPtr( ip_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(ip_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(ip_header));
	  sr.Write( bytes, 0, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
  }

  public void WriteUdpHeader(short src, short dst, short len)
  {
	WriteUdpHeader(src,dst,len,bw.BaseStream);
  }
  public void WriteUdpHeader(short src, short dst, short len, Stream sr)
  {
	udp_header.src = IPAddress.HostToNetworkOrder(src);
	udp_header.dst = IPAddress.HostToNetworkOrder(dst);
	udp_header.length = IPAddress.HostToNetworkOrder((short)( Marshal.SizeOf(udp_header) + len));

	if( UdpChecksumEnabled )
	{
		// checksum
		// 16bitで1の補数の和を求め、求まった値の1の補数を格納
		// http://www.fenix.ne.jp/~thomas/memo/ip/checksum.html
		udp_header.checksum = 0;
	}

	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(udp_header) );
	try {
	  Marshal.StructureToPtr( udp_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(udp_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(udp_header));
	  sr.Write( bytes ,0, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
  }

  public void WriteUdpData(short src, short dst, byte[] data)
  {
	WriteUdpData(src,dst,data,bw.BaseStream);
  }
  public void WriteUdpData(short src, short dst, byte[] data, Stream sr)
  {
	udp_header.src = IPAddress.HostToNetworkOrder(src);
	udp_header.dst = IPAddress.HostToNetworkOrder(dst);
	int udp_len = Marshal.SizeOf(udp_header) + data.Length;
	udp_header.length = IPAddress.HostToNetworkOrder((short)udp_len);

	if( UdpChecksumEnabled )
	{
		// checksum
		//   16bitで1の補数の和を求め、求まった値の1の補数を格納
		//   http://www.fenix.ne.jp/~thomas/memo/ip/checksum.html
		// 擬似ヘッダの構造について
		//   http://www.wdic.org/w/WDIC/%E7%96%91%E4%BC%BC%E3%83%98%E3%83%83%E3%83%80
		udp_header.checksum = 0;
		ulong sum = (ulong)(
			(ip_header.src[0]<<8) + ip_header.src[1] + (ip_header.src[2]<<8) + ip_header.src[3] +
			(ip_header.dst[0]<<8) + ip_header.dst[1] + (ip_header.dst[2]<<8) + ip_header.dst[3] +
			(ip_header.protocol) + udp_len ); // UDP擬似ヘッダ
		sum +=	(ulong)(src + dst + udp_len); // UDPヘッダ
		for ( int i=0 ; i<data.Length-1 ; i+=2)
		{
			sum +=(ulong)((data[i]<<8) + data[i+1]);
		}
		if( 0 != (data.Length%2) ) sum += (ulong)(data[data.Length-1]<<8);
		sum = (0xffff & sum) + (sum >> 16);
		sum = (0xffff & sum) + (sum >> 16);

		udp_header.checksum = IPAddress.HostToNetworkOrder((short)~sum);
	}

	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(udp_header) );
	try {
	  Marshal.StructureToPtr( udp_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(udp_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(udp_header));
//	Console.WriteLine("UDP hdr_size{0} data_len{1}", Marshal.SizeOf(udp_header) , data.Length, udp_header.length);
	  sr.Write( bytes ,0, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
	sr.Write( data ,0, data.Length);
  }

  public void WriteSctpData(short src, short dst, byte[] data)
  {
	WriteSctpData(src,dst,data,bw.BaseStream);
  }
  public void WriteSctpData(short src, short dst, byte[] data, Stream sr)
  {
	sctp_header.src = IPAddress.HostToNetworkOrder(src);
	sctp_header.dst = IPAddress.HostToNetworkOrder(dst);
	sctp_header.chunk_type = 0;
	sctp_header.chunk_flags = 3;
	int sctp_len = 16 + data.Length; // data chunk header size(16) + data length
	sctp_header.chunk_len = IPAddress.HostToNetworkOrder((short)sctp_len);
	sctp_header.stream_seq_number++;
	sctp_header.payload_proto_type = IPAddress.HostToNetworkOrder((int)25);

	IntPtr ptr = Marshal.AllocHGlobal( Marshal.SizeOf(udp_header) );
	try {
	  Marshal.StructureToPtr( sctp_header, ptr, false);
	  byte[] bytes = new byte[Marshal.SizeOf(sctp_header) ];
	  Marshal.Copy(ptr, bytes, 0, Marshal.SizeOf(sctp_header));
	  sr.Write( bytes, 0, bytes.Length);
	} finally {
	  Marshal.FreeHGlobal(ptr);
	}
	sr.Write( data, 0, data.Length);
	if( 0 != (data.Length % 4))
	{
		//padding書込み
		sr.Write( new byte[] {0, 0, 0}, 0, 4-(data.Length % 4));
	}
  }

  public void WriteUdpFrame(byte[] srcIP, short srcport, byte[] destIP, short dstport, byte[] bytes)
  {
	uint frame_len = (uint)( Marshal.SizeOf(ethernet_header) + Marshal.SizeOf(ip_header) + Marshal.SizeOf(udp_header) + bytes.Length);
	Console.WriteLine("FRAME len:{0} (eth{1} ip{2} udp{3} data{4})",
			frame_len,
			 Marshal.SizeOf(ethernet_header) , Marshal.SizeOf(ip_header) , Marshal.SizeOf(udp_header) , bytes.Length);
	ip_header.protocol = 17; // UDP
	WriteFrameHeader( frame_len, frame_len );
	WriteDummyEtherHeader();
	WriteIPHeader(srcIP, destIP, (ushort)(Marshal.SizeOf(udp_header) + bytes.Length));
	WriteUdpData(srcport, dstport, bytes);
  }

  public void WriteUdpFrameNow(byte[] srcIP, short srcport, byte[] destIP, short dstport, byte[] bytes)
  {
	uint frame_len = (uint)( Marshal.SizeOf(ethernet_header) + Marshal.SizeOf(ip_header) + Marshal.SizeOf(udp_header) + bytes.Length);
	Console.WriteLine("FRAME len:{0} (eth{1} ip{2} udp{3} data{4})",
			frame_len,
			 Marshal.SizeOf(ethernet_header) , Marshal.SizeOf(ip_header) , Marshal.SizeOf(udp_header) , bytes.Length);
	ip_header.protocol = 17; // UDP
	WriteFrameHeaderNow( frame_len, frame_len );
	WriteDummyEtherHeader();
	WriteIPHeader(srcIP, destIP, (ushort)(Marshal.SizeOf(udp_header) + bytes.Length));
	WriteUdpData(srcport, dstport, bytes);
  }

  public void WriteSctpFrameNow(byte[] srcIP, short srcport, byte[] destIP, short dstport, byte[] bytes)
  {
	uint frame_len = (uint)( Marshal.SizeOf(ethernet_header) + Marshal.SizeOf(ip_header) + Marshal.SizeOf(sctp_header));
	frame_len += (uint)((bytes.Length+3)/4)*4;
	Console.WriteLine("FRAME len:{0} (eth{1} ip{2} sctp{3} data{4})",
			frame_len,
			 Marshal.SizeOf(ethernet_header) , Marshal.SizeOf(ip_header) , Marshal.SizeOf(sctp_header) , bytes.Length);
	ip_header.protocol = 132; // SCTP
	WriteFrameHeaderNow( frame_len, frame_len );
	WriteDummyEtherHeader();
	WriteIPHeader(srcIP, destIP, (ushort)(Marshal.SizeOf(sctp_header) + ((bytes.Length+3)/4)*4 ));
	WriteSctpData(srcport, dstport, bytes);
	
  }

  public void Close()
  {
	bw.Close();
	bw = null;
  }

#if UTEST
	public static readonly DateTime dtEpoch = new DateTime(1970, 1, 1);
	static public void Main()
	{
		CapWrite cw = null;
		try{
			cw = new CapWrite();
			cw.Open( System.Windows.Forms.Application.StartupPath + @"\test.cap" );
			byte[] bytes = new byte[] {0xca,0xfe,0xca,0xfe,0xca,0xfe,0xca,0xfe};
//			byte[] bytes = new byte[] {0xca,0xfe,0xca,0xfe,0xca,0xfe,0xca};
//			byte[] bytes = new byte[] {0,0};
			uint frame_len = (uint)( Marshal.SizeOf(cw.ethernet_header) + Marshal.SizeOf(cw.ip_header) + Marshal.SizeOf(cw.udp_header) + bytes.Length);

			// フレーム出力テスト(protocol毎)
			cw.WriteFrameHeaderNow( frame_len, frame_len );
			cw.WriteDummyEtherHeader();
			cw.WriteIPHeader(new byte[] {192,168,255,1},new byte[] {192,168,255,2}, (ushort)(Marshal.SizeOf(cw.udp_header) + bytes.Length));
			cw.WriteUdpData(10000,2000, bytes);

			// フレーム出力テスト(protocol毎)
			cw.WriteFrameHeaderNow( frame_len, frame_len );
			cw.WriteDummyEtherHeader();
			cw.WriteIPHeader(new byte[] {192,168,255,1},new byte[] {192,168,255,2}, (ushort)(Marshal.SizeOf(cw.udp_header) + bytes.Length));
			cw.WriteUdpData(10000,2000, bytes);

			// フレーム出力テスト(protocol毎, 現在時刻)
			cw.WriteFrameHeaderNow( frame_len, frame_len );
			cw.WriteDummyEtherHeader();
			cw.WriteIPHeader(new byte[] {192,168,255,1},new byte[] {192,168,255,2}, (ushort)(Marshal.SizeOf(cw.udp_header) + bytes.Length));
			cw.WriteUdpData(10000,2000, bytes);

			// フレーム出力テスト(UDPフレーム全セット, 現在時刻)
			cw.WriteUdpFrameNow(new byte[] {192,168,255,1},10,new byte[] {192,168,255,2}, 20, bytes);
			cw.WriteUdpFrameNow(new byte[] {192,168,255,100},10000,new byte[] {192,168,255,200}, 20000, bytes);
			cw.WriteUdpFrameNow(new byte[] {0,0,0,0},1,new byte[] {0,0,0,0}, 1, bytes);

			System.Threading.Thread.Sleep(10);

			// フレーム出力テスト(メモリストリーム使用, 現在時刻)
			using ( MemoryStream ms = new MemoryStream() )
			{
				cw.WriteDummyEtherHeader( (Stream)ms ); // Etherヘッダの書き込み
				cw.WriteIPHeader(new byte[] {192,168,255,1},new byte[] {192,168,255,2},
					(ushort)(Marshal.SizeOf(cw.udp_header) + bytes.Length), ms); // IPヘッダの書き込み
				cw.WriteUdpData(10000,2000, bytes, (Stream)ms ); // UDPヘッダ(checksum計算)とペイロードの書き込み
				
				// Ether～UDPデータをUDPにラッピング
				cw.WriteUdpFrameNow(new byte[] {192,168,255,100},10000,new byte[] {192,168,255,200},20000, ms.ToArray() );
			}

		}catch(Exception e)
		{
			Console.WriteLine(e);
		}finally{
			if( null != cw) cw.Close();
		}
		Console.WriteLine("### Program Finished.");
		Console.ReadLine();
	}
#endif
}