package net.floodlightcontroller.radar;

import java.util.List;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IRadarService extends IFloodlightService {
	
	public enum CollectionMode {
		COLLECTION_MODE_TRIGGERIN,
		COLLECTION_MODE_ACTIVATED
	}
	
	public U64 register(String name, IRadarListener radarListerner, RadarConfiguration config);
	
	public void locate(U64 vectorId, DatapathId dpid,
			List<IPv4AddressWithMask> splitted, List<IPv4AddressWithMask> merged, List<IPv4AddressWithMask> blocked);
	
	public void changeCollectionMode(U64 vectorId, DatapathId dpid, CollectionMode mode);
	
	public U64 addDetectionVector(U64 cookie, DatapathId dpid, DetectionVectorDescriptor vector);
}
