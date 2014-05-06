using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct pcap_pkthdr {
	public int  tv_sec;         /* seconds */
	public int  tv_usec;        /* and microseconds */
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

[StructLayout(LayoutKind.Sequential)]
public struct sctp_hdstr {
  public short src;
  public short dst;
  public uint verification_tag;
  public uint checksum;
  public byte chunk_type;
  public byte chunk_flags;
  public short chunk_len;
  public int tsn;
  public short stream_id;
  public short stream_seq_number;
  public int payload_proto_type;
}

