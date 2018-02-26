package net.floodlightcontroller.radar;

import org.projectfloodlight.openflow.types.DatapathId;

public class OFSwitchPort {
	private String key;
	private DatapathId dpid;
	private int port;
	
	public OFSwitchPort(DatapathId dpid, int port) {
		this.dpid = dpid;
		this.port = port;
		
		this.key  = String.format("%s-%d", dpid.toString(), port);
	}
	
	public DatapathId getDatapathId() {
		return dpid;
	}
	
	public int getPort() {
		return port;
	}
	
	@Override
	public String toString() {
		return key;
	}
	
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        long raw = dpid.getLong() + ((long)port << 32);
        
        result = prime * result + (int) (raw ^ (raw << 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        
        OFSwitchPort swPort = (OFSwitchPort) obj;
        if (dpid == swPort.getDatapathId() && port == swPort.getPort())
    		return true;
    	return false;
    }
}
