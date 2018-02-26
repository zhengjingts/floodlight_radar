package net.floodlightcontroller.radar;

import java.util.Map;

import org.projectfloodlight.openflow.types.DatapathId;

public class UpdateEvent {
	private final DatapathId dpid;
	private final long       timestamp;
	
	private final Map<String, OFStatistic> stats;
	
	public UpdateEvent(DatapathId dpid, long timestamp, Map<String, OFStatistic> stats) {
		this.dpid      = dpid;
		this.timestamp = timestamp;
		
		this.stats    = stats;
	}
	
	public DatapathId getDatapathId() {
		return dpid;
	}
	
	public long getTimestamp() {
		return timestamp;
	}

	public Map<String, OFStatistic> getStatistic() {
		return stats;
	}
}
