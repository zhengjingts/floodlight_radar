package net.floodlightcontroller.radar;

import org.projectfloodlight.openflow.types.DatapathId;

public class OFStatistic {
	protected final DatapathId  dpid;
	protected final OFStatType  type;

	protected final long   packets;
	protected final long   bytes;
	protected final double speed;
	
	protected final long   timeStamp;
	
	public enum OFStatType {
		BASIC_STATISTIC,
		PORT_STATISTIC,
		FLOW_STATISTIC,
		LOCATION_STATISTIC
	}
	
	public OFStatistic(DatapathId dpid, OFStatType type, long packets, long bytes,
			double speed, long timeStamp) {
		this.dpid     = dpid;
		this.type     = type;
		
		this.packets = packets;
		this.bytes   = bytes;
		this.speed   = speed;
		
		this.timeStamp     = timeStamp;
	}
	
	public DatapathId getDpid() {
		return dpid;
	}

	public OFStatType getType() {
		return type;
	}
	
	public long getPackets() {
		return packets;
	}
	
	public long getBytes() {
		return bytes;
	}
	
	public long getTimeStamp() {
		return timeStamp;
	}

	public double getSpeed() {
		return speed;
	}
}
