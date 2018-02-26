package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collection;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.projectfloodlight.openflow.protocol.OFActionType;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFInstructionType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.radar.IRadarService.CollectionMode;
import net.floodlightcontroller.util.MatchUtils;

public class Amplification implements IFloodlightModule, IOFSwitchListener, IRadarListener {

	public static int port = 2000;
	
	// Basic detection parameters
	protected int    capacity  = 2;
	
	// Collection parameters
	protected int triggerInRate = 1;
	
	// Detection parameters
	protected boolean parallelDetection = true;
	
	// Split-Table control parameters
	protected int     maxFlowEntries = 10000;
	
	// Malicious source location parameters
	protected int     splitRate      = 4;
	protected int     maxSplitLevel  = 32;
	protected double  significance   = 1.0;
	protected int     score          = 3;
	
	// Merge parameters
	protected boolean mergeable = true;
	protected long    decay     = 5000;
	
	// Victim detection parameters
	protected int    avrReq  = 300;
	protected int    atkReq  = 10;
	protected double avrAmp  = 4.0;
	protected double atkAmp  = 30.0;
	
	protected double thBaseline = (avrReq*avrAmp + atkReq*atkAmp) / (avrReq+atkReq);
	protected int    thLasts    = 10;
	
	protected Map<DatapathId, SuspiciousTable> suspiciousTables;
	protected Map<DatapathId, List<IPv4AddressWithMask>> blockedAddresses;
	
	protected IFloodlightProviderService   floodlightProvider;
	protected IOFSwitchService             switchService;
	protected IRadarService                radarService;
	
	private Thread updater;
	private BlockingQueue<UpdateEvent> updateQueue;
	
	private U64 cookie;
	
	// Amplification Attack detection information
	protected Map<DatapathId, IPv4AddressWithMask> switchLAN;
	protected List<DatapathId> criticalSwitches;
	
	protected Map<U64, DatapathId> detectionVectors;
	
	// True means Source, False means Destination
	protected Map<U64, Boolean> vectorDirections;
	
	protected Map<DatapathId, Map<IPv4AddressWithMask, FlowStatistic>> historySrcFlowStats;
	protected Map<DatapathId, Map<IPv4AddressWithMask, FlowStatistic>> historyDstFlowStats;
	
	protected Map<DatapathId, Integer> historyEventTimes;
	protected List<DatapathId> amplificationOccurence;
	
	protected static Logger logger;
	
	@Override
	public void statisticUpdated(UpdateEvent update) {
		try {
			updateQueue.put(update);
		} catch (InterruptedException e) {
			logger.error("Error - Event - Put Update Event: {}", e.getStackTrace().toString());
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
				logger.error("Error - Event - Retrieve Update Event: {}", e.getStackTrace().toString());
				continue;
			}
			
			DatapathId dpid = update.getDatapathId();
			Map<String, OFStatistic> stats = update.getStatistic();
			
			Map<IPv4AddressWithMask, FlowStatistic> detSrcStats =
					new HashMap<IPv4AddressWithMask, FlowStatistic>();
			Map<IPv4AddressWithMask, FlowStatistic> detDstStats =
					new HashMap<IPv4AddressWithMask, FlowStatistic>();
			
			double totalSrcSpeed = 0.0, totalDstSpeed = 0.0;
			for (String key : stats.keySet()) {
				OFStatistic stat = stats.get(key);
				switch(stat.getType()) {
				case FLOW_STATISTIC:
					FlowStatistic flowStat = (FlowStatistic)stat;
					U64 vId = flowStat.getVectorId();
					if ( vectorDirections.get(vId)) {
						detSrcStats.put(flowStat.getAddress(), flowStat);
						logger.debug("Debug - DNS - Source Stats: {}", String.format("%s %d %d %f",
								flowStat.getAddress().toString(), flowStat.getPackets(), flowStat.getBytes(), flowStat.getSpeed()));
						totalSrcSpeed += flowStat.getSpeed();
					} else {
						detDstStats.put(flowStat.getAddress(), flowStat);
						logger.debug("Debug - DNS - Destination Stats: {}", String.format("%s %d %d %f",
								flowStat.getAddress().toString(), flowStat.getPackets(), flowStat.getBytes(), flowStat.getSpeed()));
						totalDstSpeed += flowStat.getSpeed();
					}
					break;
					
				case PORT_STATISTIC:
					break;
					
				default:
					break;
				}
			}
			
			FlowStatistic rootDstStat = detDstStats.get(IPv4AddressWithMask.of("0.0.0.0/0"));
			double amplificationRate = 0.0;
			if (totalDstSpeed != 0.0)
				amplificationRate = totalDstSpeed/totalSrcSpeed;
			
			logger.info("Experiment - Detection - Amplification Factor: {}",
					String.format("![%s] ![%f]", dpid.toString(), amplificationRate));
			
			if (amplificationRate >= thBaseline) {
				logger.info("Experiment - Detection - DNS State: {}",
						String.format("![%s] ![CRITICAL] ![%f] ![%d]",
								dpid.toString(), amplificationRate, System.currentTimeMillis()));
				
				if (!criticalSwitches.contains(dpid)) {
					criticalSwitches.add(dpid);
					radarService.changeCollectionMode(
							rootDstStat.getVectorId(), dpid, CollectionMode.COLLECTION_MODE_ACTIVATED);
				}
				
				if (!historyEventTimes.containsKey(dpid))
					historyEventTimes.put(dpid, 0);
				else {
					int lasts = historyEventTimes.get(dpid) + 1;
					historyEventTimes.put(dpid, lasts);
					if (lasts >= thLasts && !amplificationOccurence.contains(dpid)) {
						amplificationOccurence.add(dpid);
						logger.info("Experiment - Detection - Detected Amplification Attack: {}",
								String.format("![%s] ![%d]", dpid.toString(), System.currentTimeMillis())); // Experiment
					}
				}
				
				if (amplificationOccurence.contains(dpid) || parallelDetection)
					detectSuspicious(dpid, detSrcStats, detDstStats, rootDstStat.getTimeStamp());
			}
			
			if (criticalSwitches.contains(dpid)) {
				historySrcFlowStats.get(dpid).putAll(detSrcStats);
				historyDstFlowStats.get(dpid).putAll(detDstStats);
			}
		}
	}
	
	private void detectSuspicious(DatapathId dpid, Map<IPv4AddressWithMask, FlowStatistic> locSrcStats,
			Map<IPv4AddressWithMask, FlowStatistic> locDstStats, long updateTime) {
		logger.info("Experiment - Detection - Analyze Suspicious: {}",
				String.format("![%s]", dpid.toString()));
		
		Map<IPv4AddressWithMask, Double> updateValues = new HashMap<IPv4AddressWithMask, Double>();
		
		Map<IPv4AddressWithMask, FlowStatistic> historyLocSrcStats = historySrcFlowStats.get(dpid);
		Map<IPv4AddressWithMask, FlowStatistic> historyLocDstStats = historyDstFlowStats.get(dpid);
		
		for (IPv4AddressWithMask address : locDstStats.keySet()) {
//			logger.info("Debug - Location Address: {}", String.format("%s %b %b %b %b",
//					address.toString(), locSrcStats.containsKey(address), locDstStats.containsKey(address),
//					historyLocSrcStats.containsKey(address), historyLocDstStats.containsKey(address)));
			if (!locSrcStats.containsKey(address) || !historyLocSrcStats.containsKey(address)
					|| !historyLocDstStats.containsKey(address))
				continue;
			
			FlowStatistic locSrcStat = locSrcStats.get(address);
			FlowStatistic locDstStat = locDstStats.get(address);
			FlowStatistic historyLocSrcStat = historyLocSrcStats.get(address);
			FlowStatistic historyLocDstStat = historyLocDstStats.get(address);
			
			double locDstBpp = 0.0, locDstPkts = (double)(locDstStat.getPackets() - historyLocDstStat.getPackets());
			double locSrcBpp = 0.0, locSrcPkts = (double)(locSrcStat.getPackets() - historyLocSrcStat.getPackets());
			if (locDstPkts != 0.0)
				locDstBpp = (double)(locDstStat.getBytes() - historyLocDstStat.getBytes()) / locDstPkts;
			if (locSrcPkts != 0.0)
				locSrcBpp = (double)(locSrcStat.getBytes() - historyLocSrcStat.getBytes()) / locSrcPkts;
			
			double amplificationRate = 0.0;
			if (locSrcBpp != 0.0)
				amplificationRate = locDstBpp / locSrcBpp;
			
			logger.debug("Debug - Suspicious Statistics - Source: {}",
					String.format("%s %s %d %d %d %d %f", dpid.toString(), address.toString(),
							locSrcStat.getBytes(), historyLocSrcStat.getBytes(),
							locSrcStat.getPackets(), historyLocSrcStat.getPackets(), locSrcBpp));
			logger.debug("Debug - Suspicious Statistics - Destnation: {}",
					String.format("%s %s %d %d %d %d %f", dpid.toString(), address.toString(),
							locDstStat.getBytes(), historyLocDstStat.getBytes(),
							locDstStat.getPackets(), historyLocDstStat.getPackets(), locDstBpp));
			
//			if ( !(locSrcStat.getSpeed() == 0.0 ^ locSrcStat.getLatestBytes() == 0.0) )
//				logger.info("Debug - Suspicious Statistics - Error: {}",
//						String.format("%s %s %f %f", dpid.toString(), address.toString(),
//								locSrcStat.getChangeRate(), locDstStat.getChangeRate()));
			
			if (amplificationRate >= thBaseline)
				updateValues.put(address, amplificationRate - thBaseline);
			else
				updateValues.put(address, 0.0);
		}
		
		for (IPv4AddressWithMask address : updateValues.keySet()) {
			logger.debug("Debug - Suspicious Values: {}",
					String.format("%s %s %f", dpid.toString(), address.toString(), updateValues.get(address)));
		}
			
			// TODO: fix it
			// Provide correspondent location vectors to locator.
		
		List<IPv4AddressWithMask> splitted = new ArrayList<IPv4AddressWithMask>();
		List<IPv4AddressWithMask> merged   = new ArrayList<IPv4AddressWithMask>();
		List<IPv4AddressWithMask> blocked  = new ArrayList<IPv4AddressWithMask>();
		
		suspiciousTables.get(dpid).locate(updateValues, splitted, merged, blocked, updateTime);
		
		long now = System.currentTimeMillis();
		if (splitted.size() != 0 || merged.size() != 0 || blocked.size() != 0) {
			U64 srcVId = locSrcStats.get(IPv4AddressWithMask.of("0.0.0.0/0")).getVectorId();
			U64 dstVId = locDstStats.get(IPv4AddressWithMask.of("0.0.0.0/0")).getVectorId();
			
			for (IPv4AddressWithMask m : merged) {
				historySrcFlowStats.get(dpid).remove(m);
				historyDstFlowStats.get(dpid).remove(m);
			}
			
			for (IPv4AddressWithMask s : splitted) {
				historySrcFlowStats.get(dpid).put(s, new FlowStatistic(srcVId, dpid, 0, 0, 0.0, now, s.getValue(),
						s.getMask().asCidrMaskLength()));
				historyDstFlowStats.get(dpid).put(s, new FlowStatistic(dstVId, dpid, 0, 0, 0.0, now, s.getValue(),
						s.getMask().asCidrMaskLength()));
			}
			
			radarService.locate(srcVId, dpid, splitted, merged, blocked);
			radarService.locate(dstVId, dpid, splitted, merged, blocked);
		}
		
		for (IPv4AddressWithMask address : blocked) {
			List<IPv4AddressWithMask> swPortBlockedAddresses = blockedAddresses.get(dpid);
			if (!swPortBlockedAddresses.contains(address)) {
				swPortBlockedAddresses.add(address);
				logger.info("Experiment - Detection - Block: {}",
						String.format("![%s] ![%s] ![%d]", dpid.toString(), address.toString(), updateTime));
			}
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
		radarService         = context.getServiceImpl(IRadarService.class);
		
		updateQueue = new LinkedBlockingQueue<UpdateEvent>();
		
		switchLAN = new HashMap<DatapathId, IPv4AddressWithMask>();
		criticalSwitches  = new ArrayList<DatapathId>();
		historyEventTimes = new HashMap<DatapathId, Integer>();
		amplificationOccurence = new ArrayList<DatapathId>();
		
		suspiciousTables = new HashMap<DatapathId, SuspiciousTable>();
		blockedAddresses = new HashMap<DatapathId, List<IPv4AddressWithMask>>();
		
		detectionVectors = new HashMap<U64, DatapathId>();
		vectorDirections = new HashMap<U64, Boolean>();
		
		historySrcFlowStats = new HashMap<DatapathId, Map<IPv4AddressWithMask, FlowStatistic>>();
		historyDstFlowStats = new HashMap<DatapathId, Map<IPv4AddressWithMask, FlowStatistic>>();
		
		logger = LoggerFactory.getLogger(Amplification.class);
		
		setConfig(context.getConfigParams(this));
		
		// Experiment
		logger.info("Experiment - Parameter - Capacity: {}", String.format("![%d]", capacity));
		logger.info("Experiment - Parameter - Trigger-In Rate: {}", String.format("![%d]", triggerInRate));
		
		logger.info("Experiment - Parameter - Parallel Detection: {}", String.format("![%b]", parallelDetection));
		
		logger.info("Experiment - Parameter - Split Rate: {}", String.format("![%d]", splitRate));
		logger.info("Experiment - Parameter - Maximun Split Level: {}", String.format("![%d]", maxSplitLevel));
		logger.info("Experiment - Parameter - Maximum Flow Entries: {}", String.format("![%d]", maxFlowEntries));
		
		logger.info("Experiment - Parameter - Mergeable: {}", String.format("![%b]", mergeable));
		
		logger.info("Experiment - Parameter - Average Requests: {}", String.format("![%d]", avrReq));
		logger.info("Experiment - Parameter - Attack Requests: {}", String.format("![%d]", atkReq));
		logger.info("Experiment - Parameter - Average Amplification Rate: {}", String.format("![%f]", avrAmp));
		logger.info("Experiment - Parameter - Attack Amplification Rate: {}", String.format("![%f]", atkAmp));
		
		logger.info("Experiment - Parameter - Threshold Amplification Rate Baseline: {}", String.format("![%f]", thBaseline));
		logger.info("Experiment - Parameter - Threshold Lasts Time: {}", String.format("![%d]", thLasts));
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		switchService.addOFSwitchListener(this);
		
		RadarConfiguration config = new RadarConfiguration();

		config.setMaxLocationRules(maxFlowEntries);
		config.setSplitRate(splitRate);
		config.setMaxSplitLevel(maxSplitLevel);
		config.setMergeable(mergeable);
		
		cookie = radarService.register("Amplification Detector", this, config);
		
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
		getFlowRules(switchId);
		
		IPv4AddressWithMask root = IPv4AddressWithMask.of("0.0.0.0/0");
		
		DetectionVectorDescriptor detSrcVector = new DetectionVectorDescriptor(0,
				DetectionVectorDescriptor.FLOW_STATISTIC, true);
		
		detSrcVector.setMatchField(MatchUtils.STR_DL_TYPE , "0x0800");
		detSrcVector.setMatchField(MatchUtils.STR_NW_PROTO, "17");
		detSrcVector.setMatchField(MatchUtils.STR_NW_DST, switchLAN.get(switchId).toString());
		detSrcVector.setMatchField(MatchUtils.STR_UDP_DST, String.format("%d", port));
		
		U64 detSrcVectorId = radarService.addDetectionVector(cookie, switchId, detSrcVector);
		
		historySrcFlowStats.put(switchId, new HashMap<IPv4AddressWithMask, FlowStatistic>());
		historySrcFlowStats.get(switchId).put(root, new FlowStatistic(detSrcVectorId, switchId, 0, 0, 0.0,
				System.currentTimeMillis(),	root.getValue(), root.getMask().asCidrMaskLength()));
		
		DetectionVectorDescriptor detDstVector = new DetectionVectorDescriptor(triggerInRate,
				DetectionVectorDescriptor.FLOW_STATISTIC, false);
		
		detDstVector.setMatchField(MatchUtils.STR_DL_TYPE , "0x0800");
		detDstVector.setMatchField(MatchUtils.STR_NW_PROTO, "17");
		detDstVector.setMatchField(MatchUtils.STR_NW_SRC, switchLAN.get(switchId).toString());
		detDstVector.setMatchField(MatchUtils.STR_UDP_SRC, String.format("%d", port));
		
		U64 detDstVectorId = radarService.addDetectionVector(cookie, switchId, detDstVector);
		
		historyDstFlowStats.put(switchId, new HashMap<IPv4AddressWithMask, FlowStatistic>());
		historyDstFlowStats.get(switchId).put(root, new FlowStatistic(detDstVectorId, switchId, 0, 0, 0.0,
				System.currentTimeMillis(),	root.getValue(), root.getMask().asCidrMaskLength()));
		
		suspiciousTables.put(switchId, new SuspiciousTable(switchId.toString(), 
				splitRate, maxSplitLevel, maxFlowEntries, significance, score, decay, mergeable));
		blockedAddresses.put(switchId, new ArrayList<IPv4AddressWithMask>());
		
		detectionVectors.put(detSrcVectorId, switchId);
		detectionVectors.put(detDstVectorId, switchId);
		vectorDirections.put(detSrcVectorId, true);
		vectorDirections.put(detDstVectorId, false);
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
	
	@SuppressWarnings({ "unchecked" })
	private void getFlowRules(DatapathId dpid) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFStatsRequest<?> req = sw.getOFFactory().buildFlowStatsRequest()
				.setTableId(TableId.of(RadarManager.firstForwardingTbl))
				.build();
		
		ListenableFuture<?> future;
		List<OFMessage> values;
		
		try {
			future = sw.writeStatsRequest(req);
			values = (List<OFMessage>) future.get(RadarManager.timeout, RadarManager.timeUnit);
		} catch (Exception e) {
			logger.error("Error - Request - Retrieve Flow Rules: {}", e.getStackTrace().toString());
			return;
		}
		
		for (OFMessage value : values) {
			OFFlowStatsReply flowStats = (OFFlowStatsReply)value;
			for (OFFlowStatsEntry e : flowStats.getEntries()) {
				
				// A hacking way to retrieve local /24 block of net
				List<OFInstruction> instructions = e.getInstructions();
				for (OFInstruction instruction : instructions) {
					if (instruction.getType() == OFInstructionType.APPLY_ACTIONS) {
						OFInstructionApplyActions applyActions = (OFInstructionApplyActions)instruction;
						
						List<OFAction> actions = applyActions.getActions();
						for (OFAction action : actions) {
							if (action.getType() == OFActionType.OUTPUT) {
								OFActionOutput output = (OFActionOutput)action;
								if (output.getPort().getPortNumber() == 1) {
									IPv4AddressWithMask address =
											IPv4AddressWithMask.of(
													e.getMatch().getMasked(MatchField.IPV4_DST).getValue(),
													e.getMatch().getMasked(MatchField.IPV4_DST).getMask());
									switchLAN.put(dpid, address);
									logger.info("Debug - Info - Switch & Net Block  Mapping: {}",
											String.format("%s %s", dpid.toString(), address.toString()));
									return;
								}
							}
						}
					}
				}
				
			}
		}
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
        
        String sParallelDetection = configParams.get("parallelDetection");
        if (!Strings.isNullOrEmpty(sParallelDetection)) {
            try {
            	parallelDetection = Boolean.parseBoolean(sParallelDetection);
            } catch (NumberFormatException e) {
                logger.error("Error - Setting - Invalid parallel detection specifier:", e);
            }
            logger.info("Experiment - Setting - Parallele Detection: {}", String.format("![%b]", parallelDetection));
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
        
//        String sMinSplitLevel = configParams.get("minSplitLevel");
//        if (!Strings.isNullOrEmpty(sMinSplitLevel)) {
//            try {
//            	minSplitLevel = Integer.parseInt(sMinSplitLevel);
//            } catch (NumberFormatException e) {
//                logger.error("Error - Setting - Invalid minimum split level specifier:", e);
//            }
//            logger.info("Experiment - Setting - Minimum Split Level: {}", String.format("![%d]", minSplitLevel));
//        }

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
        
//        String sMinSplitLevel = configParams.get("minSplitLevel");
//        if (!Strings.isNullOrEmpty(sMinSplitLevel)) {
//            try {
//            	minSplitLevel = Integer.parseInt(sMinSplitLevel);
//            } catch (NumberFormatException e) {
//                logger.error("Invalid minimum split level specifier", e);
//            }
//            logger.info("Experiment - Setting - Minimum Split Level: {}", minSplitLevel);
//        }
        
        String sAvrReq = configParams.get("averageRequests");
        if (!Strings.isNullOrEmpty(sAvrReq)) {
            try {
            	avrReq = Integer.parseInt(sAvrReq);
            } catch (NumberFormatException e) {
                logger.error("Invalid average requests specifier", e);
            }
            logger.info("Experiment - Setting - Average Requests: {}", avrReq);
        }
        
        String sAtkReq = configParams.get("attackRequests");
        if (!Strings.isNullOrEmpty(sAtkReq)) {
            try {
            	atkReq = Integer.parseInt(sAtkReq);
            } catch (NumberFormatException e) {
                logger.error("Invalid attack requests specifier", e);
            }
            logger.info("Experiment - Setting - Attack Requests: {}", atkReq);
        }
        
        String sAvrAmp = configParams.get("averageAmplificationRate");
        if (!Strings.isNullOrEmpty(sAvrAmp)) {
            try {
            	avrAmp = Double.parseDouble(sAvrAmp);
            } catch (NumberFormatException e) {
                logger.error("Invalid average amplification rate specifier", e);
            }
            logger.info("Experiment - Setting - Average Amplification Rate: {}", avrAmp);
        }
        
        String sAtkAmp = configParams.get("attackAmplificationRate");
        if (!Strings.isNullOrEmpty(sAtkAmp)) {
            try {
            	atkAmp = Double.parseDouble(sAtkAmp);
            } catch (NumberFormatException e) {
                logger.error("Invalid attack amplification rate specifier", e);
            }
            logger.info("Experiment - Setting - Attack Amplification Rate: {}", atkAmp);
        }
		
        String sThLasts = configParams.get("thLasts");
        if (!Strings.isNullOrEmpty(sThLasts)) {
            try {
            	thLasts = Integer.parseInt(sThLasts);
            } catch (NumberFormatException e) {
                logger.error("Invalid threshold lasts time specifier", e);
            }
            logger.info("Experiment - Setting - Threshold Lasts Time: {}", thLasts);
        }
        
		thBaseline = (avrReq*avrAmp + atkReq*atkAmp) / (avrReq+atkReq);
	}
}
