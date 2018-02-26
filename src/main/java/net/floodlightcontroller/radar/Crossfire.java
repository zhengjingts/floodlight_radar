package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collection;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.U64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.radar.IRadarService.CollectionMode;
import net.floodlightcontroller.util.MatchUtils;

public class Crossfire implements IFloodlightModule, IOFSwitchListener, ILinkDiscoveryListener, IRadarListener {

	// Basic detection parameters
	protected int    capacity       = 2;
	protected double thWarning      = 0.65;
	protected double thCongestion   = 0.85;
	
	// Collection parameters
	protected int triggerInRate = 2000;
	
	// Detection parameters
	protected boolean parallelDetection = true;
	
	// Crossfire Attack detection parameters
	protected int     thMinWaves        = 3;
	protected int     thMinLinks        = 2;
	protected double  thTimeCoverage    = 0.9;
	
	// Split-Table control parameters
	protected int maxFlowEntries = 10000;
	
	// Malicious source location parameters
	protected int    splitRate     = 4;
	protected int    maxSplitLevel = 24;
	protected double significance  = 0.99;
	protected int    score         = 3;
	
	// Merge parameters
	protected boolean mergeable = true;
	protected long    decay     = 30000;
	
	protected Map<OFSwitchPort, SuspiciousTable> suspiciousTables;
	protected Map<OFSwitchPort, List<IPv4AddressWithMask>> blockedAddresses;
	
	protected IFloodlightProviderService   floodlightProvider;
	protected IOFSwitchService             switchService;
	protected ILinkDiscoveryService        linkDiscoveryService;
	protected IRadarService                radarService;
	
	private Thread updater;
	private BlockingQueue<UpdateEvent> updateQueue;
	
	private U64 cookie;
	private Map<U64, OFSwitchPort> detectionVectorIds;
	private Map<OFSwitchPort, U64> switchPortVectorIds;
	
	// Crossfire Attack detection information
	protected Map<OFSwitchPort, OFLink>  links;
	protected List<DatapathId>           criticalSwitches;
	protected Map<OFSwitchPort, Integer> criticalPortWaves;
	
	protected Map<OFSwitchPort, PortStatistic>                           historyPortStats;
	protected Map<OFSwitchPort, Map<IPv4AddressWithMask, FlowStatistic>> historyFlowStats;
	
	protected Map<OFSwitchPort, List<Long>>  historyEventTimes;
	protected boolean                        crossfireOccurence;
	
	protected static Logger logger;
	
	@Override
	public void statisticUpdated(UpdateEvent update) {
		try {
			updateQueue.put(update);
		} catch (InterruptedException e) {
			logger.error("Error - Event - Put Update Event:", e);
		}
	}
		
	protected void updateThread() {
		UpdateEvent update;
		while (true) {
			try {
				update = updateQueue.take();
				logger.info("Experiment - Event - Updated: {}", String.format("![%s] ![%d]",
						update.getDatapathId().toString(), System.currentTimeMillis()));
			} catch (InterruptedException e) {
				logger.error("Error - Event - Retrieve Update Event:", e);
				continue;
			}
			
			DatapathId dpid = update.getDatapathId();
			Map<String, OFStatistic> stats = update.getStatistic();
			
			Map<OFSwitchPort, PortStatistic> portStats = new HashMap<OFSwitchPort, PortStatistic>();
			Map<OFSwitchPort, Map<IPv4AddressWithMask, FlowStatistic>> locStats =
					new HashMap<OFSwitchPort, Map<IPv4AddressWithMask, FlowStatistic>>();
			
			for (String key : stats.keySet()) {
				OFStatistic stat = stats.get(key);
				switch(stat.getType()) {
				case PORT_STATISTIC:
					PortStatistic portStat = (PortStatistic)stat;
					portStats.put(portStat.getSwitchPort(), portStat);
					break;
					
				case FLOW_STATISTIC:
					FlowStatistic flowStat = (FlowStatistic)stat;
					OFSwitchPort swPort = detectionVectorIds.get(flowStat.getVectorId());
					
					if (swPort == null)
						break;
					
					if (!locStats.containsKey(swPort))
						locStats.put(swPort, new HashMap<IPv4AddressWithMask, FlowStatistic>());
					
					locStats.get(swPort).put(flowStat.getAddress(), flowStat);
					break;
					
				default:
					break;
				}
			}
			
			for (OFSwitchPort swPort : portStats.keySet()) {
				PortStatistic portStat = portStats.get(swPort);
				Map<IPv4AddressWithMask, FlowStatistic> flowStats = locStats.get(swPort);
				
				if (!links.containsKey(swPort))
					continue;
				
				if (portStat.getSpeed() >= thWarning * capacity && !criticalPortWaves.containsKey(swPort)) {
					logger.info("Experiment - Detection - Change to Activated Collection Mode: {}",
							String.format("![%s]", swPort.toString()));
					
					criticalPortWaves.put(swPort, 0);
					
					if (!criticalSwitches.contains(dpid)) {
						criticalSwitches.add(dpid);
						radarService.changeCollectionMode(switchPortVectorIds.get(portStat.getSwitchPort()),
								dpid, CollectionMode.COLLECTION_MODE_ACTIVATED);
					}
				}
				
				if (historyPortStats.containsKey(swPort)) {
					PortStatistic historyPortStat = historyPortStats.get(swPort);
					if (portStat.getSpeed() <= thWarning * capacity) {
						if (historyPortStat.getSpeed() <= thWarning * capacity) {
							logger.info("Experiment - Detection - Port State: {}",
									String.format("![%s-%d] ![NORMAL -> NORMAL] ![%f] ![%f] ![%f] ![%d]",
											swPort.getDatapathId().toString(), swPort.getPort(),
											portStat.getSpeed(), portStat.getRxSpeed(),
											portStat.getRxSpeed() - historyPortStat.getRxSpeed(),
											portStat.getTimeStamp()));
						}
						else if (historyPortStat.getSpeed() >= thCongestion * capacity) {
							logger.info("Experiment - Detection - Port State: {}",
									String.format("![%s-%d] ![CONGESTION -> NORMAL] ![%f] ![%f] ![%f] ![%d]",
											swPort.getDatapathId().toString(), swPort.getPort(),
											portStat.getSpeed(), portStat.getRxSpeed(),
											portStat.getRxSpeed() - historyPortStat.getRxSpeed(),
											portStat.getTimeStamp()));
							criticalPortWaves.put(swPort, criticalPortWaves.get(swPort)+1);
							
							if (historyEventTimes.get(swPort) != null)
								historyEventTimes.get(swPort).add(portStat.getTimeStamp());
							
							if (!crossfireOccurence)
								crossfireOccurence = detectCrossfire();
							
							if (crossfireOccurence || parallelDetection)
								detectSuspicious(swPort, portStat, flowStats, portStat.getTimeStamp());
						}
					} else if(portStat.getSpeed() >= thCongestion * capacity) {
						if (historyPortStat.getSpeed() >= thCongestion * capacity) {
							logger.info("Experiment - Detection - Port State: {}",
									String.format("![%s-%d] ![CONGESTION -> CONGESTION] ![%f] ![%f] ![%f] ![%d]",
											swPort.getDatapathId().toString(), swPort.getPort(),
											portStat.getSpeed(), portStat.getRxSpeed(),
											portStat.getRxSpeed() - historyPortStat.getRxSpeed(),
											portStat.getTimeStamp()));
						}
						else if (historyPortStat.getSpeed() <= thWarning * capacity) {
							logger.info("Experiment - Detection - Port State: {}",
									String.format("![%s-%d] ![NORMAL -> CONGESTION] ![%f] ![%f] ![%f] ![%d]",
											swPort.getDatapathId().toString(), swPort.getPort(),
											portStat.getSpeed(), portStat.getRxSpeed(),
											portStat.getRxSpeed() - historyPortStat.getRxSpeed(),
											portStat.getTimeStamp()));
							
							if (!historyEventTimes.containsKey(swPort))
								historyEventTimes.put(swPort, new ArrayList<Long>());
							historyEventTimes.get(swPort).add(portStat.getTimeStamp());
							
							if (crossfireOccurence || parallelDetection)
								detectSuspicious(swPort, portStat, flowStats, portStat.getTimeStamp());
						}
					}
				}
				
				if (portStat.getSpeed() <= thWarning * capacity || portStat.getSpeed() >= thCongestion * capacity) {
					historyPortStats.put(swPort, portStat);
					historyFlowStats.put(swPort, flowStats);
				}
			}
		}
	}
	
	private boolean detectCrossfire() {
		// Experiment
		logger.info("Experiment - Event - Detect Crossfire: {}",
				String.format("![%d]", System.currentTimeMillis()));
		
		ArrayList<OFLink> attackedLinks = new ArrayList<OFLink>();
		for(OFSwitchPort swPort : criticalPortWaves.keySet())
			if(criticalPortWaves.get(swPort) >= thMinWaves) {
				OFLink link = links.get(swPort);
				if (!attackedLinks.contains(link))
					attackedLinks.add(link);
			}
		
		// Experiment
		logger.info("Experiment - Detection - Attacked Links: {}",
				String.format("![%s] ![%d]", attackedLinks.toString(), attackedLinks.size()));
		
		if(attackedLinks.size() < thMinLinks)
			return false;
		
		long now = System.currentTimeMillis();
		ArrayList<Long> riseTimeSeries = new ArrayList<Long>();
		ArrayList<Long> fallTimeSeries = new ArrayList<Long>();
		for (OFLink attackedLink : attackedLinks) {
			for (OFSwitchPort swPort : attackedLink.getSwitchPorts()) {
				ArrayList<Long> swPortTimeSeries = (ArrayList<Long>) historyEventTimes.get(swPort);
				if (swPortTimeSeries == null)
					continue;
				for (int i = 0; i < swPortTimeSeries.size(); i += 2) {
					riseTimeSeries.add(swPortTimeSeries.get(i));
					if (i+1 < swPortTimeSeries.size())
						fallTimeSeries.add(swPortTimeSeries.get(i+1));
				}
			}
		}
		
		Collections.sort(riseTimeSeries);
		Collections.sort(fallTimeSeries);
		
		int i = 0, j = 0;
		int underAttack = 0;
		ArrayList<Long> congestionTimeSeries = new ArrayList<Long>();
		while (i < riseTimeSeries.size() && j < fallTimeSeries.size()) {
			if (riseTimeSeries.get(i) <= fallTimeSeries.get(j)) {
				long time = riseTimeSeries.get(i);
				if (underAttack == 0)
					congestionTimeSeries.add(time);
				underAttack += 1;
				i ++;
			} else {
				long time = fallTimeSeries.get(j);
				underAttack -= 1;
				if (underAttack == 0)
					congestionTimeSeries.add(time);
				j ++;
			}
		}
		
		if (i < riseTimeSeries.size() && underAttack == 0) {
				congestionTimeSeries.add(riseTimeSeries.get(i));
		}
		
		while (j < fallTimeSeries.size()) {
			long time = fallTimeSeries.get(j);
			underAttack -= 1;
			if (underAttack == 0) {
				congestionTimeSeries.add(time);
				break;
			}
			j ++;
		}
		
		long timeLength = 0;
		int  sig = -1;
		for(long t : congestionTimeSeries) {
			timeLength += sig * t;
			sig *= -1;
		}
		
		if(timeLength == 0)
			return false;
		
		if(timeLength < 0)
			timeLength += now;
		
		double coverage = ((double)timeLength)/(now-congestionTimeSeries.get(0));
		
		logger.info("Experiment - Detection - Congestion Coverage: {}",
				String.format("![%s] ![%f]", historyEventTimes.toString(), coverage)); // Experiment
		if( coverage >= thTimeCoverage) {
			logger.info("Experiment - Detection - Detected Crossfire Attack: {}",
					String.format("![%f] ![%d]", coverage, System.currentTimeMillis())); // Experiment
			return true;
		}
		return false;
	}
	
	private void detectSuspicious(OFSwitchPort swPort, PortStatistic portStat,
			Map<IPv4AddressWithMask, FlowStatistic> flowsStats, long updateTime) {
		
		logger.info("Experiment - Event - Detect Suspicious: {}",
				String.format("![%s] ![%d]", swPort.toString(), portStat.getTimeStamp()));
		
		Map<IPv4AddressWithMask, FlowStatistic> prevFlowsStats = historyFlowStats.get(swPort);
		if (prevFlowsStats == null)
			return;
		
		int sig = (portStat.getRxSpeed() - historyPortStats.get(swPort).getRxSpeed()) >= 0.0 ? 1 : -1;
		SuspiciousTable suspiciousTable = suspiciousTables.get(swPort);
		Map<IPv4AddressWithMask, Double> updateValues = new HashMap<IPv4AddressWithMask, Double>();
		
		for (IPv4AddressWithMask address : flowsStats.keySet()) {
			if (!prevFlowsStats.containsKey(address))
				continue;
			
			double added = sig * (flowsStats.get(address).getSpeed()/portStat.getTxLossRate()
					- prevFlowsStats.get(address).getSpeed()/historyPortStats.get(swPort).getTxLossRate());
			
			updateValues.put(address, added);
			logger.info("Debug - Update Values: {}",
					String.format("![%s] ![%s] ![%f]", swPort.toString(), address.toString(),
							updateValues.get(address)));
		}
		
		List<IPv4AddressWithMask> splitted = new ArrayList<IPv4AddressWithMask>();
		List<IPv4AddressWithMask> merged   = new ArrayList<IPv4AddressWithMask>();
		List<IPv4AddressWithMask> blocked  = new ArrayList<IPv4AddressWithMask>();
		
		suspiciousTable.locate(updateValues, splitted, merged, blocked, updateTime);
		
		if (splitted.size() != 0 || merged.size() != 0 || blocked.size() != 0) {
			U64 vId = flowsStats.get(IPv4AddressWithMask.of("0.0.0.0/0")).getVectorId();
			
			for (IPv4AddressWithMask m : merged) {
				historyFlowStats.get(swPort).remove(m);
				historyFlowStats.get(swPort).remove(m);
			}
			
			radarService.locate(vId, swPort.getDatapathId(), splitted, merged, blocked);
		}
		
		for (IPv4AddressWithMask address : blocked) {
			List<IPv4AddressWithMask> swPortBlockedAddresses = blockedAddresses.get(swPort);
			if (!swPortBlockedAddresses.contains(address)) {
				swPortBlockedAddresses.add(address);
				logger.info("Experiment - Detection - Block: {}",
						String.format("![%s] ![%s] ![%d]", swPort.toString(), address.toString(), updateTime));
			}
		}
	}
	
	protected class OFLink {
		private List<OFSwitchPort> swPorts;
		
		private String key;
		
		public OFLink(OFSwitchPort sp1, OFSwitchPort sp2) {
			swPorts = new ArrayList<OFSwitchPort>();
			swPorts.add(sp1);
			swPorts.add(sp2);
			
			this.key = String.format("<%s : %s>", sp1.toString(), sp2.toString());
		}
		
		public OFLink(DatapathId src, int srcPort, DatapathId dst, int dstPort) {
			OFSwitchPort sp1 = new OFSwitchPort(src, srcPort);
			OFSwitchPort sp2 = new OFSwitchPort(dst, dstPort);
			
			swPorts = new ArrayList<OFSwitchPort>();
			swPorts.add(sp1);
			swPorts.add(sp2);
			
			this.key = String.format("<%s : %s>", sp1.toString(), sp2.toString());
		}
		
		public List<OFSwitchPort> getSwitchPorts() {
			return swPorts;
		}
		
		@Override
		public String toString() {
			return key;
		}
		
	    @Override
	    public int hashCode() {
	        final int prime = 31;
	        int result = 1;
	        
	        result = prime * result + (int) (swPorts.get(0).hashCode() ^ swPorts.get(1).hashCode());
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
	        
	        OFLink link = (OFLink) obj;
	        if (swPorts.get(0) == link.swPorts.get(0) && swPorts.get(1) == link.swPorts.get(1))
	        	return true;
	        if (swPorts.get(0) == link.swPorts.get(1) && swPorts.get(1) == link.swPorts.get(0))
	        	return true;
	    	return false;
	    }
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IOFSwitchService.class);
	    l.add(ILinkDiscoveryService.class);
	    l.add(IRadarService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider   = context.getServiceImpl(IFloodlightProviderService.class);
		switchService        = context.getServiceImpl(IOFSwitchService.class);
		linkDiscoveryService = context.getServiceImpl(ILinkDiscoveryService.class);
		radarService         = context.getServiceImpl(IRadarService.class);
		
		suspiciousTables = new HashMap<OFSwitchPort, SuspiciousTable>();
		blockedAddresses = new HashMap<OFSwitchPort, List<IPv4AddressWithMask>>();
		
		updateQueue = new LinkedBlockingQueue<UpdateEvent>();
		
		detectionVectorIds  = new HashMap<U64, OFSwitchPort>();
		switchPortVectorIds = new HashMap<OFSwitchPort, U64>();
		
		links              = new HashMap<OFSwitchPort, OFLink>();
		criticalSwitches   = new ArrayList<DatapathId>();
		criticalPortWaves  = new HashMap<OFSwitchPort, Integer>();
		historyEventTimes  = new HashMap<OFSwitchPort, List<Long>>();
		crossfireOccurence = false;
		
		historyPortStats   = new HashMap<OFSwitchPort, PortStatistic>();
		historyFlowStats   = new HashMap<OFSwitchPort, Map<IPv4AddressWithMask, FlowStatistic>>();
		
		logger = LoggerFactory.getLogger(Crossfire.class);
		
		setConfig(context.getConfigParams(this));
		
		// Experiment
		logger.info("Experiment - Parameter - Capacity: {}", String.format("![%d]", capacity));
		logger.info("Experiment - Parameter - Trigger-In: {}", String.format("![%d]", triggerInRate));
		logger.info("Experiment - Parameter - Warning Threshold: {}", String.format("![%f]", thWarning));
		logger.info("Experiment - Parameter - Congestion Threshold: {}", String.format("![%f]", thCongestion));

		logger.info("Experiment - Parameter - Parallel Detection: {}", String.format("![%b]", parallelDetection));
		
		logger.info("Experiment - Parameter - Minimum Congestion Waves: {}", String.format("![%d]", thMinWaves));
		logger.info("Experiment - Parameter - Minimum Congestion Links: {}", String.format("![%d]", thMinLinks));
		logger.info("Experiment - Parameter - Minimum Congestion Time Coverage: {}", String.format("![%f]", thTimeCoverage));
		
		logger.info("Experiment - Parameter - Maximum Flow Entries: {}", String.format("![%d]", maxFlowEntries));
		
//		logger.info("Experiment - Parameter - Minimun Split Level: {}", String.format("![%d]", minSplitLevel));
		logger.info("Experiment - Parameter - Maximun Split Level: {}", String.format("![%d]", maxSplitLevel));
		logger.info("Experiment - Parameter - Split Rate: {}", String.format("![%d]", splitRate));
		logger.info("Experiment - Parameter - Significance: {}", String.format("![%f]", significance));
		logger.info("Experiment - Parameter - Score: {}", String.format("![%d]", score));
		
		logger.info("Experiment - Parameter - Mergeable: {}", String.format("![%b]", mergeable));
		logger.info("Experiment - Parameter - Decay Waves: {}", String.format("![%d]", decay));

//		logger.debug("Experiment - Parameter - Ignore Crossfire Detection: {}", String.format("![%b]", ignoreDetection));
//		logger.debug("Experiment - Parameter - Maximum Split Times: {}", String.format("![%d]", maxSplits));
		
//		logger.debug("Experiment - Parameter - Decay Value: {}", String.format("![%f]", thDecayValue));
//		logger.debug("Experiment - Parameter - Decay Time: {}", String.format("![%d]", thDecayTime));
		
//		logger.debug("Experiment - Parameter - Suspicious Threshold: {}", String.format("![%f]", thMaxSuspicious));
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		switchService.addOFSwitchListener(this);
		linkDiscoveryService.addListener(this);
		
		RadarConfiguration config = new RadarConfiguration();

		config.setMaxLocationRules(maxFlowEntries);
		config.setSplitRate(splitRate);
//		config.setMinSplitLevel(minSplitLevel);
		config.setMaxSplitLevel(maxSplitLevel);
		config.setMergeable(mergeable);
		config.setScore(score);
		config.setDecay(decay);
		
		cookie = radarService.register("Crossfire Detector", this, config);
		
		updater = new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					updateThread();
				}
			}
		}, "Updater");
		updater.start();
	}

	@Override
	public void switchAdded(DatapathId switchId) {	
		
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		
	}

	@Override
	public void linkDiscoveryUpdate(LDUpdate update) {
		switch (update.getOperation()) {
		case PORT_UP:
			break;
			
		case LINK_UPDATED:
			
			if (update.getType() != LinkType.DIRECT_LINK)
				break;
			
			OFSwitchPort sp1 = new OFSwitchPort(update.getSrc(), update.getSrcPort().getPortNumber());
			OFSwitchPort sp2 = new OFSwitchPort(update.getDst(), update.getDstPort().getPortNumber());
			
			if (!links.containsKey(sp1)) {
				OFLink link = new OFLink(sp1, sp2);
				
				links.put(sp1, link);
				links.put(sp2, link);
				
				DetectionVectorDescriptor vector1 = new DetectionVectorDescriptor(triggerInRate,
						DetectionVectorDescriptor.FLOW_STATISTIC + DetectionVectorDescriptor.PORT_STATISTIC, true);
				vector1.setMatchField(MatchUtils.STR_IN_PORT, String.format("%d", sp1.getPort()));
				vector1.setMatchField(MatchUtils.STR_DL_TYPE, "0x0800");
				
				DetectionVectorDescriptor vector2 = new DetectionVectorDescriptor(triggerInRate,
						DetectionVectorDescriptor.FLOW_STATISTIC + DetectionVectorDescriptor.PORT_STATISTIC, true);
				vector2.setMatchField(MatchUtils.STR_IN_PORT, String.format("%d", sp2.getPort()));
				vector2.setMatchField(MatchUtils.STR_DL_TYPE, "0x0800");
				
				U64 vId1 = radarService.addDetectionVector(cookie, update.getSrc(), vector1);
				U64 vId2 = radarService.addDetectionVector(cookie, update.getDst(), vector2);
				detectionVectorIds.put(vId1, sp1);
				detectionVectorIds.put(vId2, sp2);
				switchPortVectorIds.put(sp1, vId1);
				switchPortVectorIds.put(sp2, vId2);
				
				suspiciousTables.put(sp1, new SuspiciousTable(sp1.toString(), 
						splitRate, maxSplitLevel, maxFlowEntries, significance, score, decay, mergeable));
				suspiciousTables.put(sp2, new SuspiciousTable(sp2.toString(), 
						splitRate, maxSplitLevel, maxFlowEntries, significance, score, decay, mergeable));
				blockedAddresses.put(sp1, new ArrayList<IPv4AddressWithMask>());
				blockedAddresses.put(sp2, new ArrayList<IPv4AddressWithMask>());
				
				IPv4AddressWithMask root = IPv4AddressWithMask.of("0.0.0.0/0");
				historyFlowStats.put(sp1, new HashMap<IPv4AddressWithMask, FlowStatistic>());
				historyFlowStats.put(sp2, new HashMap<IPv4AddressWithMask, FlowStatistic>());
				
				historyFlowStats.get(sp1).put(root, new FlowStatistic(vId1, sp1.getDatapathId(), 0, 0, 0.0,
						System.currentTimeMillis(), root.getValue(), root.getMask().asCidrMaskLength()));
				historyFlowStats.get(sp2).put(root, new FlowStatistic(vId2, sp2.getDatapathId(), 0, 0, 0.0,
						System.currentTimeMillis(), root.getValue(), root.getMask().asCidrMaskLength()));
			}
			
			logger.info("Experiment - Event - Link Updated: {}",
					String.format("![%s-%d] ![%s-%d]",
							sp1.getDatapathId().toString(), sp1.getPort(), sp2.getDatapathId().toString(), sp2.getPort()));

		default: 
			break;
		}
	}

	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		for (LDUpdate update : updateList)
			linkDiscoveryUpdate(update);
	}
	
	private void setConfig(Map<String, String> configParams) {
		
		String sCapacity = configParams.get("capacity");
        if (!Strings.isNullOrEmpty(sCapacity)) {
            try {
                capacity = Integer.parseInt(sCapacity);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid capacity specifier:", e);
            }
            logger.info("Experiment - Setting - Capacity: {}", String.format("![%d]", capacity));
        }
        
        String sTriggerInRate = configParams.get("triggerInRate");
        if (!Strings.isNullOrEmpty(sTriggerInRate)) {
            try {
                triggerInRate = Integer.parseInt(sTriggerInRate);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid trigger-in rate specifier:", e);
            }
            logger.info("Experiment - Setting - Trigger-In Rate: {}", String.format("![%d]", triggerInRate));
        }
        
        
        String sThWarning = configParams.get("thWarning");
        if (!Strings.isNullOrEmpty(sThWarning)) {
            try {
            	thWarning = Double.parseDouble(sThWarning);

            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid threshold warning specifier:", e);
            }
            logger.info("Experiment - Setting - Threshold Warning: {}", String.format("![%f]", thWarning));
        }
        
        String sThCongestion = configParams.get("thCongestion");
        if (!Strings.isNullOrEmpty(sThCongestion)) {
            try {
            	thCongestion = Double.parseDouble(sThCongestion);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid threshold congestion specifier:", e);
            }
            logger.info("Experiment - Setting - Threshold Congestion: {}", String.format("![%f]", thCongestion));
        }
        
        String sParallelDetection = configParams.get("parallelDetection");
        if (!Strings.isNullOrEmpty(sParallelDetection)) {
            try {
            	parallelDetection = Boolean.parseBoolean(sParallelDetection);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid parallel detection specifier:", e);
            }
            logger.info("Experiment - Setting - Parallele Detection: {}", String.format("![%b]", parallelDetection));
        }
        
        String sThMinWaves = configParams.get("thMinWaves");
        if (!Strings.isNullOrEmpty(sThMinWaves)) {
            try {
            	thMinWaves = Integer.parseInt(sThMinWaves);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid threshold minimum waves specifier:", e);
            }
            logger.info("Experiment - Setting - Threshold Minimum Waves: {}", String.format("![%d]", thMinWaves));
        }
        
        String sThMinLinks = configParams.get("thMinLinks");
        if (!Strings.isNullOrEmpty(sThMinLinks)) {
            try {
            	thMinLinks = Integer.parseInt(sThMinLinks);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid threshold minimum links specifier:", e);
            }
            logger.info("Experiment - Setting - Threshold Minimum Links: {}", String.format("![%d]", thMinLinks));
        }
        
        String sThTimeCoverage = configParams.get("thTimeCoverage");
        if (!Strings.isNullOrEmpty(sThTimeCoverage)) {
            try {
            	thTimeCoverage = Double.parseDouble(sThTimeCoverage);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid threshold congestion time coverage specifier:", e);
            }
            logger.info("Experiment - Setting - Threshold Congestion Time Coverage: {}",
            		String.format("![%f]", thTimeCoverage));
        }
        
        
        String sMaxFlowEntries = configParams.get("maxFlowEntries");
        if (!Strings.isNullOrEmpty(sMaxFlowEntries)) {
            try {
            	maxFlowEntries = Integer.parseInt(sMaxFlowEntries);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid maximum flow entries specifier:", e);
            }
            logger.info("Experiment - Setting - Maximum Flow Entries: {}", String.format("![%d]", maxFlowEntries));
        }
        
        String sMaxSplitLevel = configParams.get("maxSplitLevel");
        if (!Strings.isNullOrEmpty(sMaxSplitLevel)) {
            try {
            	maxSplitLevel = Integer.parseInt(sMaxSplitLevel);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid maximum split level specifier:", e);
            }
            logger.info("Experiment - Setting - Maximum Split Level: {}", String.format("![%d]", maxSplitLevel));
        }
        
        String sSplitRate = configParams.get("splitRate");
        if (!Strings.isNullOrEmpty(sSplitRate)) {
            try {
            	splitRate = Integer.parseInt(sSplitRate);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid split rate specifier:", e);
            }
            logger.info("Experiment - Setting - Split Rate: {}", String.format("![%d]", splitRate));
        }
        
        String sSignificance = configParams.get("significance");
        if (!Strings.isNullOrEmpty(sSignificance)) {
            try {
            	significance = Double.parseDouble(sSignificance);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid significance rate specifier:", e);
            }
            logger.info("Experiment - Setting - Significance Rate: {}", String.format("![%f]", significance));
        }
        
        String sScore = configParams.get("score");
        if (!Strings.isNullOrEmpty(sScore)) {
            try {
            	score = Integer.parseInt(sScore);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid score specifier:", e);
            }
            logger.info("Experiment - Setting - Score: {}", String.format("![%d]", score));
        }
        
        
        String sMergeable = configParams.get("mergeable");
        if (!Strings.isNullOrEmpty(sMergeable)) {
            try {
            	mergeable = Boolean.parseBoolean(sMergeable);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid mergeable specifier:", e);
            }
            logger.info("Experiment - Setting - Mergeable: {}", String.format("![%b]", mergeable));
        }
        
        String sDecay = configParams.get("decay");
        if (!Strings.isNullOrEmpty(sDecay)) {
            try {
            	decay = Integer.parseInt(sDecay);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid decay waves specifier:", e);
            }
            logger.info("Experiment - Setting - Decay Waves: {}", String.format("![%d]", decay));
        }
	}
}
