package net.floodlightcontroller.radar;

import org.projectfloodlight.openflow.types.DatapathId;

public class PortStatistic extends OFStatistic {
	
	private final OFSwitchPort swPort;
	
	private final long rxPackets;
	private final long txPackets;
	
	private final long rxBytes;
	private final long txBytes;
	
	private final double rxSpeed;
	private final double txSpeed;
	
	private final long   rxDropped;
	private final long   txDropped;
	private final double txLossRate;
	
	public PortStatistic(DatapathId dpid, long packets, long bytes,
			double speed, long timeStamp, OFSwitchPort swPort, long rxPackets, long txPackets,
			long rxBytes, long txBytes,	double rxSpeed, double txSpeed,
			long rxDropped, long txDropped, double txLossRate) {
		super(dpid, OFStatType.PORT_STATISTIC, packets, bytes, speed, timeStamp);
		
		this.swPort = swPort;
		
		this.rxPackets = rxPackets;
		this.txPackets = txPackets;
		
		this.rxBytes = rxBytes;
		this.txBytes = txBytes;
		
		this.rxSpeed = rxSpeed;
		this.txSpeed = txSpeed;
		
		this.rxDropped  = rxDropped;
		this.txDropped  = txDropped;
		this.txLossRate = txLossRate;
	}
	
	public OFSwitchPort getSwitchPort() {
		return swPort;
	}

	public long getRxPackets() {
		return rxPackets;
	}

	public long getTxPackets() {
		return txPackets;
	}
	
	public long getRxBytes() {
		return rxBytes;
	}

	public long getTxBytes() {
		return txBytes;
	}
	
	public double getRxSpeed() {
		return rxSpeed;
	}

	public double getTxSpeed() {
		return txSpeed;
	}
	
	public long getRxDropped() {
		return rxDropped;
	}
	
	public long getTxDropped() {
		return txDropped;
	}
	
	public double getTxLossRate() {
		return txLossRate;
	}
}
