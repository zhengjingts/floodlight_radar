package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFBucket;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFGroupAdd;
import org.projectfloodlight.openflow.protocol.OFGroupDelete;
import org.projectfloodlight.openflow.protocol.OFGroupMod;
import org.projectfloodlight.openflow.protocol.OFGroupType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionDecNwTtl;
import org.projectfloodlight.openflow.protocol.action.OFActionGroup;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public class Dummy implements IOFMessageListener, IOFSwitchListener, IFloodlightModule {

	// Services
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService           switchService;
	
	protected Thread activeCollectionTask;
	protected Thread universalCollectionTask;
	
	protected Trace collectionTrace;
	
	protected long   minInterval  = 1000;

	// Switch flow entries parameters
	protected int samplingWeight = 2000;
	protected int baseWeight     = 1;
	
	protected int criticals = 0;
	
	protected static final int controlTbl        = 0;
	protected static final int currentMonitorTbl = 50;
	protected static final int lastMonitorTbl    = 51;
	protected static final int forwardingTbl     = 100;

	protected static final int basicPriority  = 0;
	protected static final int arpPriority    = 50;
	protected static final int blockPriority  = 60;
	
	protected int group_id = 1;
	
	// Logger
	protected static Logger logger;
	
	// Packet-In message handler
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() == OFType.PACKET_IN) {
			OFPacketIn pktin = (OFPacketIn)msg;
			if (pktin.getTableId().equals(TableId.of(currentMonitorTbl))) {
				String swkey = sw.getId().toString();
				
				long now = System.currentTimeMillis();
				synchronized (collectionTrace) {
					if (!collectionTrace.containsTrace(swkey))
						return Command.CONTINUE;
					if (collectionTrace.isActivated(swkey) || now - collectionTrace.getLatestTrace(swkey) < 1000)
						return Command.CONTINUE;
					collectionTrace.setLatestTrace(swkey, now);
				}
				
				logger.info("Experiment - Task - Trigger-In Tasks: {}",
						String.format("![%s] ![%d]", swkey, System.currentTimeMillis()));	// Experiment
				
				return Command.CONTINUE;
			}
		}
		
		return Command.CONTINUE;
	}
	
	private class Trace {
		private Map<String, Boolean> activated;
		private Map<String, Long>    latestTrace;
		private Map<String, Long>    activatedTrace;
		
		public Trace() {
			activated      = new HashMap<String, Boolean>();
			latestTrace    = new HashMap<String, Long>();
			activatedTrace = new HashMap<String, Long>();
		}
		
		public void addKey(String key) {
			activated.put(key, false);
			latestTrace.put(key, System.currentTimeMillis());
		}
		
		public boolean containsTrace(String key) {
			return latestTrace.containsKey(key);
		}
		
		public boolean isActivated(String key) {
			return activated.get(key);
		}
		
		public long getLatestTrace(String key) {
			return latestTrace.get(key);
		}
		
		public Map<String, Long> getActivatedTrace() {
			return activatedTrace;
		}
		
		public void setActivated(String key, boolean isActivated) {
			activated.put(key, isActivated);
			if (isActivated == true)
				activatedTrace.put(key, System.currentTimeMillis());
			else
				activatedTrace.remove(key);
		}
		
		public void setLatestTrace(String key, long latest) {
			latestTrace.put(key, latest);
		}
		
		public void incrActivatedTrace(String key, long span) {
			activatedTrace.put(key, activatedTrace.get(key) + span);
		}
	}
	
	public void changeTriggerRate(DatapathId dpid, int weight) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFActionDecNwTtl dec_ttl = sw.getOFFactory().actions().decNwTtl();
		OFActionOutput to_ctrl = sw.getOFFactory().actions().buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER)
				.build();
		
		List<OFAction> al1 = new ArrayList<OFAction>();
		al1.add(dec_ttl);
		al1.add(to_ctrl);
		
		List<OFAction> al2 = new ArrayList<OFAction>();
		al2.add(dec_ttl);
		
		List<OFBucket> buckets = new ArrayList<OFBucket>();
		buckets.add(
				sw.getOFFactory().buildBucket()
					.setWatchGroup(OFGroup.ANY)
					.setWatchPort(OFPort.ANY)
					.setWeight(baseWeight)
					.setActions(al1)
					.build());
		if (weight > 0) {
			buckets.add(
					sw.getOFFactory().buildBucket()
						.setWatchGroup(OFGroup.ANY)
						.setWatchPort(OFPort.ANY)
						.setWeight(weight-1)
						.setActions(al2)
						.build());
		}
		
		OFGroupMod groupMod = sw.getOFFactory().buildGroupModify()
				//TODO: hack code
				.setGroup(OFGroup.of(1))
				.setGroupType(OFGroupType.SELECT)
				.setBuckets(buckets)
				.build();
		
		sw.write(groupMod);
		sw.flush();
	}
	
	// Initialize flow tables and group tables
	private void initDefaultRules(IOFSwitch sw) {
		;
		// Clear all rules.
		OFFlowDelete flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.of(controlTbl))
				.build();
		sw.write(flowdel);
		
		flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.of(currentMonitorTbl))
				.build();
		sw.write(flowdel);
		
		flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.of(lastMonitorTbl))
				.build();
		sw.write(flowdel);
		
		// Clear all groups.
		OFGroupDelete groupDel = sw.getOFFactory().buildGroupDelete()
				.setGroup(OFGroup.ALL)
				.setGroupType(OFGroupType.SELECT)
				.build();
		sw.write(groupDel);
		
		// Add group
		OFActionDecNwTtl dec_ttl = sw.getOFFactory().actions().decNwTtl();
		OFActionOutput to_ctrl = sw.getOFFactory().actions().buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER)
				.build();
		
		List<OFAction> al1 = new ArrayList<OFAction>();
		al1.add(dec_ttl);
		al1.add(to_ctrl);
		
		List<OFAction> al2 = new ArrayList<OFAction>();
		al2.add(dec_ttl);
		
		OFBucket b1 = sw.getOFFactory().buildBucket()
				.setWatchGroup(OFGroup.ANY)
				.setWatchPort(OFPort.ANY)
				.setWeight(baseWeight)
				.setActions(al1)
				.build();
		
		OFBucket b2 = sw.getOFFactory().buildBucket()
				.setWatchGroup(OFGroup.ANY)
				.setWatchPort(OFPort.ANY)
				.setWeight(samplingWeight-1)
				.setActions(al2)
				.build();

		List<OFBucket> buckets = new ArrayList<OFBucket>();
		buckets.add(b1);
		buckets.add(b2);
		
		OFGroupAdd groupAdd = sw.getOFFactory().buildGroupAdd()
				// TODO: hack code
				.setGroup(OFGroup.of(1))
				.setGroupType(OFGroupType.SELECT)
				.setBuckets(buckets)
				.build();
		
		sw.write(groupAdd);
		
		// Control Table: Add goto-monitor-table rule
		OFInstruction gotoDetectionTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(currentMonitorTbl));
		List<OFInstruction> gotoDctTbl = new ArrayList<OFInstruction>();
		gotoDctTbl.add(gotoDetectionTable);
		
		OFFlowAdd controlTableAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(controlTbl))
				.setInstructions(gotoDctTbl)
				.build();
		sw.write(controlTableAdd);
		
		// Monitor Table: Add goto-forwarding-table rule
		OFActionGroup goto_group = sw.getOFFactory().actions()
				// TODO: Hack code
				.group(OFGroup.of(1));
		List<OFAction> aplActions = new ArrayList<OFAction>();
		aplActions.add(goto_group);
		
		OFInstruction gotoLastTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(lastMonitorTbl));
		OFInstruction appl_act = sw.getOFFactory().instructions()
				.applyActions(aplActions);
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(gotoLastTable);
		instructions.add(appl_act);
		
		OFFlowAdd currentTableAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(currentMonitorTbl))
				.setInstructions(instructions)
				.build();
		sw.write(currentTableAdd);
		
		OFInstruction gotoForwardingTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(forwardingTbl));
		List<OFInstruction> gotoFwdTblInst = new ArrayList<OFInstruction>();
		gotoFwdTblInst.add(gotoForwardingTable);
		OFFlowAdd lastTableAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(lastMonitorTbl))
				.setInstructions(gotoFwdTblInst)
				.build();
		sw.write(lastTableAdd);
		
		// Forwarding Table: Add packet-in rule
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(to_ctrl);
		
		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(forwardingTbl))
				.setMatch(
						sw.getOFFactory().buildMatch().build())
				.setActions(actions)
				.build();
		sw.write(flowAdd);
	}
	
	private void activeCollectionThread() throws InterruptedException{
		long now, minWait;
		
		while(true) {
			now = System.currentTimeMillis();
			minWait = minInterval;
			List<String> criticalSwitches = new ArrayList<String>();
			
			synchronized(collectionTrace) {
				Map<String, Long> activatedTrace = collectionTrace.getActivatedTrace();
				for (String key : activatedTrace.keySet()) {
					long past = now - activatedTrace.get(key);
					if (past >= minInterval)
						criticalSwitches.add(key);
					else if (minWait > minInterval - past)
						minWait = past;
				}
			}
			
			for (String key : criticalSwitches) {
				logger.info("Experiment - Task - Active-Collection Tasks: {}",
						String.format("![%s] ![%d]", key, System.currentTimeMillis()));	// Experiment
			}
		
			synchronized(collectionTrace) {
				for (String key : criticalSwitches) {
					collectionTrace.setLatestTrace(key, now);
					collectionTrace.incrActivatedTrace(key, minInterval);
				}
			}
			
			Thread.sleep(minWait);
		}
	}
	
	private void universalCollectionThread() throws InterruptedException{
		long now;
		
		while(true) {
			now = System.currentTimeMillis();

			for (DatapathId dpid : switchService.getAllSwitchDpids()) {
				logger.info("Experiment - Task - Universal-Collection Tasks: {}",
						String.format("![%s] ![%d]", dpid.toString(), System.currentTimeMillis()));	// Experiment
			}
			
			Thread.sleep(now + minInterval - System.currentTimeMillis());
		}
	}

	@Override
	public void switchAdded(DatapathId switchId) {
//		logger.info("Switch Added: {}", switchId.toString());
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		// TODO: Support multi-detection modules
		initDefaultRules(sw);
		
		String key = switchId.toString();
		collectionTrace.addKey(key);
		if (criticals > 0) {
			collectionTrace.setActivated(key, true);
			changeTriggerRate(switchId, 0);
			criticals --;
		}
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
	
	// Initialize module
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// Initialize services
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		
		collectionTrace = new Trace();
		
		// Logger
		logger = LoggerFactory.getLogger(Dummy.class);
		
		activeCollectionTask = new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					try {
						activeCollectionThread();
					} catch (InterruptedException e) {
						return;
					}
				}
			}
		}, "Active Collection");
		activeCollectionTask.start();
		
		universalCollectionTask = new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					try {
						universalCollectionThread();
					} catch (InterruptedException e) {
						return;
					}
				}
			}
		}, "Universal Collection");
		universalCollectionTask.start();
		
		setConfig(context.getConfigParams(this));
		
		// Experiment
		logger.info("Experiment - Parameter - Sampling Rate: {}", String.format("![%d]", samplingWeight));
		logger.info("Experiment - Parameter - Criticals: {}", String.format("![%d]", criticals));
	}

	// Module startup
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// Add event listeners
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		switchService.addOFSwitchListener(this);
	}
	
	@Override
	public String getName() {
		return Dummy.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
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
		return l;
	}
	
	private void setConfig(Map<String, String> configParams) {
		
        String sSamplingRate = configParams.get("samplingRate");
        if (!Strings.isNullOrEmpty(sSamplingRate)) {
            try {
            	samplingWeight = Integer.parseInt(sSamplingRate);
            } catch (NumberFormatException e) {
                logger.error("Invalid sampling rate specifier", e);
            }
            logger.info("Experiment - Setting - Sampling Rate: {}", sSamplingRate);
        }
        
        String sCriticals = configParams.get("criticals");
        if (!Strings.isNullOrEmpty(sSamplingRate)) {
            try {
            	criticals = Integer.parseInt(sCriticals);
            } catch (NumberFormatException e) {
                logger.error("Invalid criticals specifier", e);
            }
            logger.info("Experiment - Setting - Criticals: {}", sCriticals);
        }
	}
}
