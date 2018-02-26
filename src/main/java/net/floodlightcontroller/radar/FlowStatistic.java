package net.floodlightcontroller.radar;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.U64;

public class FlowStatistic extends OFStatistic {
	
	protected final U64 vectorId;
	
	protected final IPv4Address ip;
	protected final int         prefix;
	
	protected final IPv4AddressWithMask address;
	
	public FlowStatistic(U64 vectorId, DatapathId dpid, long packets, long bytes,
			double speed, long timeStamp, IPv4Address ip, int prefix) {
		super(dpid, OFStatType.FLOW_STATISTIC, packets, bytes, speed, timeStamp);
		
		this.vectorId = vectorId;
		
		this.ip       = ip;
		this.prefix   = prefix;
		
		this.address = IPv4AddressWithMask.of(ip, IPv4Address.ofCidrMaskLength(prefix));
	}
	
	public U64 getVectorId() {
		return vectorId;
	}
	
	public IPv4Address getIP() {
		return ip;
	}
	
	public int getPrefix() {
		return prefix;
	}
	
	public IPv4AddressWithMask getAddress() {
		return address;
	}
}
