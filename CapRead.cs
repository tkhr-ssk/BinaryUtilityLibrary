/// Copyright (C) 2012 SASAKI Takahiro All Rights Reserved ///
using System;
using System.IO;
using System.Text;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct pcap_pkthdr {
    public    int    tv_sec;         /* seconds */
    public    int    tv_usec;        /* and microseconds */
	public uint caplen; //	/* length of portion present */
	public uint len;    //	/* length this packet (off wire) */
};
[StructLayout(LayoutKind.Sequential)]
public struct ethernet_hdstr {
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
  public byte[] dst;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
  public byte[] src;
  public short type;
}
[StructLayout(LayoutKind.Sequential)]
public struct ip_hdstr {
  public byte version_length;
  public byte differentiated_services_field;
  public ushort total_length;
  public short identification;
  public short flags;
  public byte time_to_live;
  public byte protocol;
  public short checksum;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
  public byte[] src;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
  public byte[] dst;
}
[StructLayout(LayoutKind.Sequential)]
public struct tcp_hdstr {
  public byte src_u; public byte src_l;
  public byte dst_u; public byte dst_l;
  public byte seq0; public byte seq1; public byte seq2; public byte seq3; 
  public byte ack0; public byte ack1; public byte ack2; public byte ack3; 
  public byte length;
  public byte flags;
  public byte window_u; public byte window_l;
  public byte checksum_u; public byte checksum__l;
}
[StructLayout(LayoutKind.Sequential)]
public struct udp_hdstr {
  public short src;
  public short dst;
  public short length;
  public short checksum;
}

public class EthIpUdpData {
	public ethernet_hdstr eth;
	public ip_hdstr ip;
	public udp_hdstr udp;
	public byte[] data;

	[StructLayout(LayoutKind.Sequential)]
	public struct eth_ip_udp_hdr {
	  public ethernet_hdstr eth;
	  public ip_hdstr ip;
	  public udp_hdstr udp;
	}
	protected const short ETH_TYPE_IP = 0x0800;
	protected const byte IP_PROTOCOL_UDP = 17;
	
	private EthIpUdpData(){}
	static EthIpUdpData GetEthIpUdpData(byte[] ethIpUdpData){
		eth_ip_udp_hdr EthIpUdpHdr = new eth_ip_udp_hdr();
		if( ethIpUdpData.Length < Marshal.SizeOf(EthIpUdpHdr)) return null;

		EthIpUdpHdr = BinUtil.Bytes2Structure<eth_ip_udp_hdr>(ethIpUdpData);
		EthIpUdpHdr.eth.type = IPAddress.HostToNetworkOrder(EthIpUdpHdr.eth.type);
		if( EthIpUdpHdr.eth.type != ETH_TYPE_IP ) return null;
		if( EthIpUdpHdr.ip.protocol != IP_PROTOCOL_UDP ) return null;
		EthIpUdpHdr.udp.src = IPAddress.HostToNetworkOrder(EthIpUdpHdr.udp.src);
		EthIpUdpHdr.udp.dst = IPAddress.HostToNetworkOrder(EthIpUdpHdr.udp.dst);
		EthIpUdpHdr.udp.length = IPAddress.HostToNetworkOrder(EthIpUdpHdr.udp.length);
		EthIpUdpHdr.udp.checksum = IPAddress.HostToNetworkOrder(EthIpUdpHdr.udp.checksum);
		
		
		EthIpUdpData ethIpUdpObj = new EthIpUdpData();
		ethIpUdpObj.eth = EthIpUdpHdr.eth;
		ethIpUdpObj.ip = EthIpUdpHdr.ip;
		ethIpUdpObj.udp = EthIpUdpHdr.udp;
		ethIpUdpObj.data = DumpLib.GetBytes(ethIpUdpData, Marshal.SizeOf(EthIpUdpHdr), EthIpUdpHdr.udp.length );
		return ethIpUdpObj;
	}
}
public class UdpData {
	public udp_hdstr udp;
	public byte[] data;
	private UdpData(){}
	static UdpData GetUdpData(byte[] udpData){
		UdpData udpDataObj= new UdpData();
		if( udpData.Length < Marshal.SizeOf(udpDataObj.udp)) return null;
		udpDataObj.udp = new udp_hdstr();
		udpDataObj.udp = BinUtil.Bytes2Structure<udp_hdstr>(udpData);
		udpDataObj.udp.src = IPAddress.HostToNetworkOrder(udpDataObj.udp.src);
		udpDataObj.udp.dst = IPAddress.HostToNetworkOrder(udpDataObj.udp.dst);
		udpDataObj.udp.length = IPAddress.HostToNetworkOrder(udpDataObj.udp.length);
		udpDataObj.udp.checksum = IPAddress.HostToNetworkOrder(udpDataObj.udp.checksum);
		udpDataObj.data = DumpLib.GetBytes(udpData, Marshal.SizeOf(udpDataObj.udp), udpDataObj.udp.length );
		return udpDataObj;
	}
}
public class CapFrame {
  public pcap_pkthdr PcapFrameHeader;
  public byte[] data;
	[StructLayout(LayoutKind.Sequential)]
	public struct udp_frame {
	  public ethernet_hdstr eth;
	  public ip_hdstr ip;
	  public udp_hdstr udp;
	}
  protected const short ETH_TYPE_IP = 0x0800;
  protected const byte IP_PROTOCOL_UDP = 17;
  public byte[] GetUdpData()
  {
	return this.GetUdpData(this.data);
  }
  public byte[] GetUdpData(byte[] data)
  {
	byte[] bytes = null;
	udp_frame UdpFrame = new udp_frame();
	if( data.Length >= Marshal.SizeOf(UdpFrame))
	{
		UdpFrame = BinUtil.Bytes2Structure<udp_frame>(data);
		
		UdpFrame.eth.type = IPAddress.HostToNetworkOrder(UdpFrame.eth.type);
//		Console.Write("[eth]{0:X4}",UdpFrame.eth.type);
		if( UdpFrame.eth.type != ETH_TYPE_IP ) return null;
//		Console.Write("[ip]{0}", UdpFrame.ip.protocol);
		if( UdpFrame.ip.protocol != IP_PROTOCOL_UDP ) return null;
		UdpFrame.udp.src = IPAddress.HostToNetworkOrder(UdpFrame.udp.src);
		UdpFrame.udp.dst = IPAddress.HostToNetworkOrder(UdpFrame.udp.dst);
		UdpFrame.udp.length = IPAddress.HostToNetworkOrder(UdpFrame.udp.length);
		UdpFrame.udp.checksum = IPAddress.HostToNetworkOrder(UdpFrame.udp.checksum);
//		Console.Write("[UDP]");
//		Console.Write(" src:{0}",UdpFrame.udp.src);
//		Console.Write(" dst:{0}",UdpFrame.udp.dst);
//		Console.Write(" length:{0}",UdpFrame.udp.length);
//		Console.Write(" checksum:{0:X4}",UdpFrame.udp.checksum);
		bytes = DumpLib.GetBytes(data, Marshal.SizeOf(UdpFrame), UdpFrame.udp.length );
	}
	return bytes;
  }

	protected uint Decode(uint t)
	{
		t = (uint)IPAddress.HostToNetworkOrder( (Int32)t );
		return t;
	}
	protected ushort Decode(ushort t)
	{
		t = (ushort)IPAddress.HostToNetworkOrder( (Int16)t );
		return t;
	}

  protected static readonly DateTime dtEpoch = new DateTime(1970, 1, 1);
  public string GetTimeString()
  {
	DateTime dt = dtEpoch.AddSeconds(this.PcapFrameHeader.tv_sec);
	string str = dt.ToLocalTime().ToString("yyyy/MM/dd HH:mm:ss")
				+ String.Format(".{0:D6}", this.PcapFrameHeader.tv_usec);
	return str;
  }
  public string GetTimeString(uint tv_sec, uint tv_usec)
  {
	DateTime dt = dtEpoch.AddSeconds(tv_sec);
	string str = dt.ToLocalTime().ToString("yyyy/MM/dd HH:mm:ss")
				+ String.Format(".{0:D6}", tv_usec);
	return str;
  }
  public string GetTimeStringUtc(uint tv_sec, uint tv_usec)
  {
	DateTime dt = dtEpoch.AddSeconds(tv_sec);
	string str = dt.ToString("yyyy/MM/dd HH:mm:ss")
				+ String.Format(".{0:D6}", tv_usec);
	return str;
  }
}

public class CapRead {

  public bool UdpChecksumEnabled = true;

  protected pcap_pkthdr pcap_header;
  protected ethernet_hdstr ethernet_header;
  protected ip_hdstr ip_header;
  protected udp_hdstr udp_header;
//  tcp_hdstr tcp_header;

  private byte[] FILE_HEADER =
	{0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

  private byte[] READ_FILE_HEADER;

  protected BinaryReader br = null;
  
  public CapRead()
  {

  }

  public void Open(string FileName)
  {
	br = new BinaryReader(File.Open( FileName , FileMode.Open) );
	READ_FILE_HEADER = br.ReadBytes( FILE_HEADER.Length);
  }

  public CapFrame ReadFrame()
  {
	byte[] data;
	CapFrame cap = new CapFrame();
	data = br.ReadBytes( Marshal.SizeOf(cap.PcapFrameHeader) );
	if( data.Length < Marshal.SizeOf(cap.PcapFrameHeader) ) return null;
	cap.PcapFrameHeader = BinUtil.Bytes2Structure<pcap_pkthdr>(data);
	cap.data = br.ReadBytes( (int)cap.PcapFrameHeader.caplen );
	return cap;
  }

  public void Close()
  {
	if( br != null )
	{
		br.Close();
		br = null;
	}
  }

#if CAPREAD_UTEST
//	public static readonly DateTime dtEpoch = new DateTime(1970, 1, 1);
	static public void Main(string[] args)
	{
		string ReadFile;
		if( args.Length > 0 )
		{
			ReadFile = args[0];
		}
		else
		{
			ReadFile = System.Windows.Forms.Application.StartupPath + @"\test.cap";
		}
		CapRead cr = null;
		try{
			cr = new CapRead();
			cr.Open( ReadFile );
			int count=0;
			CapFrame frame = null;
			frame = cr.ReadFrame();
			while ( null != frame )
			{
				count++;
//				Console.Write("No.{0}", count);
///				Console.Write(" {0}", frame.GetTimeString());
//				Console.WriteLine();
//				Console.Write(" Frame[tv_sec={0}, tv_usec={1}, caplen={2}, len={3}]",
//					frame.PcapFrameHeader.tv_sec,
//					frame.PcapFrameHeader.tv_usec,
//					frame.PcapFrameHeader.caplen,
//					frame.PcapFrameHeader.len);
//				DateTime dt = dtEpoch.AddSeconds(frame.PcapFrameHeader.tv_sec);
//				Console.Write(dt.ToLocalTime().ToString("(yyyy/MM/dd HH:mm:ss") );
//				Console.Write(".{0:D6})", frame.PcapFrameHeader.tv_usec);
//				Console.Write("({0})", frame.GetTimeString());
//				Console.Write(" DataLength={0}", frame.data.Length);
//				Console.WriteLine();
				frame.GetUdpData();
//				Console.WriteLine();
				frame = cr.ReadFrame();
			}
			Console.WriteLine("Count:{0}", count);
		}catch(Exception e)
		{
			Console.WriteLine(e);
		}finally{
			if( null != cr) cr.Close();
		}
		Console.WriteLine();
		Console.WriteLine("### Program Finished.");
		Console.ReadLine();
	}
#endif
}