package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.projectfloodlight.openflow.protocol.OFBucket;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFGroupAdd;
import org.projectfloodlight.openflow.protocol.OFGroupDelete;
import org.projectfloodlight.openflow.protocol.OFGroupMod;
import org.projectfloodlight.openflow.protocol.OFGroupType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFPortStatsEntry;
import org.projectfloodlight.openflow.protocol.OFPortStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionDecNwTtl;
import org.projectfloodlight.openflow.protocol.action.OFActionGroup;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

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
import net.floodlightcontroller.radar.RadarManager.Task;
import net.floodlightcontroller.radar.RadarManager.TaskType;
import net.floodlightcontroller.util.MatchUtils;

public class RadarManagerHW implements IOFMessageListener, 
				IOFSwitchListener, IFloodlightModule, IRadarService {

	// Services
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService           switchService;
	
	// Classes
	protected Collector collector;
	protected Scheduler scheduler;
	protected Locator   locator;
	
	protected Trace     trace;
	
	// Event control
	protected Map<U64, String> detectorNames;
	protected Map<U64, IRadarListener> radarListeners;
	
	// Configurations
	protected Map<U64, RadarConfiguration> configurations;
	
	protected Map<U64, DetectionVectorDescriptor> detectionVectors;
	protected Map<DatapathId, List<U64>> switchDetectionVectors;
	
	// Maintained statistic
	protected Map<DatapathId, Map<String, OFStatistic>> historyStats;
	
	// Maintain allocated tables
	protected Map<U64, Integer> detectionTableAllocation;
	protected Map<U64, Integer> groupTableAllocation;
	
	// Table ID parameters
	private Map<DatapathId, Integer> currentDetectionTbl;
	private Map<DatapathId, Integer> currentGroupTbl;
	
	// Parameters
	private static final U64 cookieHeader = U64.parseHex("A500000000000000");
	private static final U64 headerMask   = U64.parseHex("FF00000000000000");
	private static final U64 cookieMask   = U64.parseHex("FFFFFFFF00000000");
	private static final U64 vectorMaks   = U64.parseHex("00000000FFFFFFFF");
	
	protected static final int numWorker = 6;
	
	public static final int firstDetectionTbl  = 0;
	public static final int firstForwardingTbl = 100;

	public static final int basicPriority     = 0;
	public static final int detectionPriority = 100;
	public static final int arpPriority       = 50;
	public static final int blockPriority     = 60;

	public static final int      timeout    = 2000;
	public static final TimeUnit timeUnit   = TimeUnit.MILLISECONDS;
	
	protected static final long   minInterval  = 1000;
	
	// Logger
	protected static Logger logger;
	
	// Task types
	protected enum TaskType {
		ADD_FLOW_RULE,
		DEL_FLOW_RULE,
		MOD_FLOW_RULE,
		ADD_GROUP_TBL,
		DEL_GROUP_TBL,
		MOD_GROUP_TBL,
		COL_PORT_STATS,
		COL_FLOW_STATS,
	}
		
	protected class Task {
		private TaskType   type;
		private DatapathId dpid;
		private OFMessage  message;
		
		private List<OFMessage> replies;
		private BlockingQueue<Task> outputQueue;
			
		private long timeStamp;
		
		public Task(TaskType type, DatapathId dpid, OFMessage message) {
			this.type     = type;
			this.dpid     = dpid;
			this.message  = message;
			
			this.outputQueue = null;
			
			this.timeStamp = System.currentTimeMillis();
		}
		
		public Task(TaskType type, DatapathId dpid, OFMessage message, BlockingQueue<Task> outputQueue) {
			this.type     = type;
			this.dpid     = dpid;
			this.message  = message;
			
			this.outputQueue = outputQueue;
			
			this.timeStamp = System.currentTimeMillis();
		}
		
		public TaskType getType() {
			return type;
		}
		
		public DatapathId getDatapathId() {
			return dpid;
		}
		
		public OFMessage getOFMessage() {
			return message;
		}
		
		public List<OFMessage> getReplies() {
			return replies;
		}
		
		public void setReplies(List<OFMessage> replies) {
			this.replies = replies;
		}
		
		public BlockingQueue<Task> getOutputQueue() {
			return outputQueue;
		}
		
		public long getTimeStamp() {
			return timeStamp;
		}
	}
	
	@Override
	public U64 register(String name, IRadarListener radarListerner, RadarConfiguration config) {
		U64 cookie;
		Random r = new Random(System.currentTimeMillis());
		
		while (true) {
			cookie = U64.of(r.nextLong()).applyMask(U64.parseHex("00FFFFFF00000000"));
			cookie = cookie.or(cookieHeader);
			if (!radarListeners.containsKey(cookie))
				break;
		}
		
		detectorNames.put(cookie, name);
		radarListeners.put(cookie, radarListerner);
		configurations.put(cookie, config);
		
		logger.info("Experiment - Event - Register: {}",
				String.format("![%s] ![%s] ![%d]", cookie.toString(), name, System.currentTimeMillis()));
		
		return cookie;
	}

	@Override
	public void changeCollectionMode(U64 vectorId, DatapathId dpid, CollectionMode mode) {
		// Experiment
		logger.info("Experiment - Event - Change Collection Mode: {}",
				String.format("![%s] ![%s] ![%s] ![%d]", dpid.toString(), vectorId.toString(), mode.toString(),
						System.currentTimeMillis()));
		
		if (mode == CollectionMode.COLLECTION_MODE_ACTIVATED) {
			addGroupTable(dpid, groupTableAllocation.get(vectorId), 0, false);
			synchronized (trace) {
				trace.setActivated(dpid, vectorId, true);
			}
		} else {
			addGroupTable(dpid, groupTableAllocation.get(vectorId), detectionVectors.get(vectorId).getTriggerRate(), false);
			synchronized (trace) {
				trace.setActivated(dpid, vectorId, false);
			}
		}
	}

	@Override
	public void locate(U64 vectorId, DatapathId dpid, List<IPv4AddressWithMask> splitted, List<IPv4AddressWithMask> merged,
			List<IPv4AddressWithMask> blocked) {
		logger.info("Experiment - Control - Locate Suspectes: {}",
				String.format("![%s] ![%d]", vectorId.toString(), System.currentTimeMillis()));
		locator.split(vectorId, dpid, splitted, merged);
	}
	
	@Override
	public U64 addDetectionVector(U64 cookie, DatapathId dpid, DetectionVectorDescriptor vector) {
		U64 vectorId;
		Random r = new Random(System.currentTimeMillis());
		
		if (!radarListeners.containsKey(cookie))
			return null;
		
		while (true) {
			vectorId = U64.of(r.nextLong()).applyMask(vectorMaks);
			vectorId = cookie.or(vectorId);
			if (!detectionVectors.containsKey(vectorId))
				break;
		}
		
		vector.setVectorId(vectorId);
		detectionVectors.put(vectorId, vector);
		switchDetectionVectors.get(dpid).add(vectorId);
		
		if (!detectionTableAllocation.containsKey(vectorId)) {
			int tableId = currentDetectionTbl.get(dpid);
			detectionTableAllocation.put(vectorId, tableId);
			addDefaultGotoTblRule(dpid, tableId + 1, firstForwardingTbl);
			addDefaultGotoTblRule(dpid, tableId, tableId + 1);
			currentDetectionTbl.put(dpid, tableId + 1);
		}
		
		if (vector.getStatType() != DetectionVectorDescriptor.NONE_STATISTIC) {
			int groupId = currentGroupTbl.get(dpid);
			groupTableAllocation.put(vectorId, groupId);
			currentGroupTbl.put(dpid, groupId+1);
		}
		
		logger.info("Experiment - Event - Add Detection Vector: {}",
				String.format("![%s] ![%s] ![%s] ![%d]",
						dpid.toString(), cookie.toString(), vectorId.toString(), System.currentTimeMillis()));
		
		addDetectionRule(vectorId, dpid);
		
		return vectorId;
	}
	
//	@Override
//	public U64 addLocationVector(U64 cookie, DatapathId dpid, LocationVectorDescriptor vector) {
//		U64 vectorId;
//		Random r = new Random(System.currentTimeMillis());
//		
//		if (!radarListeners.containsKey(cookie))
//			return null;
//		
//		while (true) {
//			vectorId = U64.of(r.nextLong()).applyMask(vectorMaks);
//			vectorId = cookie.or(vectorId);
//			if (!detectionVectors.containsKey(vectorId) && !locationVectors.containsKey(vectorId))
//				break;
//		}
//		
//		vector.setVectorId(vectorId);
//		locationVectors.put(vectorId, vector);
//		
//		if (!locationTableAllocation.containsKey(vectorId)) {
//			int tableId = currentLocationTbl.get(dpid);
//			locationTableAllocation.put(vectorId, tableId);
//			addDefaultGotoTblRule(dpid, tableId + 1, firstForwardingTbl);
//			addDefaultGotoTblRule(dpid, tableId, tableId + 1);
//			currentLocationTbl.put(dpid, tableId + 1);
//		}
//		
//		logger.info("Experiment - Event - Add Location Vector: {}",
//				String.format("![%s] ![%s] ![%s] ![%d]",
//						dpid.toString(), cookie.toString(), vectorId.toString(), System.currentTimeMillis()));
//		
//		List<IPv4AddressWithMask> initRule = new ArrayList<IPv4AddressWithMask>();
//		initRule.add(IPv4AddressWithMask.of("0.0.0.0/0"));
//		addLocationRules(vectorId, dpid, initRule);
//		
//		return vectorId;
//	}
	
	protected class Collector {
		private BlockingQueue<List<Task>> repliesQueue;
		
		private TransactionManager transactionManager;
		private Thread dispatcher;
		private Thread activator;
		
		public Collector() {
			repliesQueue = new LinkedBlockingQueue<List<Task>>();
			
			transactionManager = new TransactionManager();
			transactionManager.start();
			
			// Initialize event control threads
			dispatcher = new Thread(new Runnable() {
				@Override
				public void run() {
					while (true) {
						try {
							dispatchThread();
						} catch (InterruptedException e) {
							return;
						}
					}
				}
			}, "Dispatcher");
			dispatcher.start();
			
			activator = new Thread(new Runnable() {
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
			}, "Activator");
			activator.start();
		}
		
		private void dispatchThread() throws InterruptedException {
			while(true) {
				List<Task> tasks = repliesQueue.take();
				
				DatapathId dpid = null;
				Map<U64, Map<String, OFStatistic>> stats = new HashMap<U64, Map<String, OFStatistic>>();
				
				for (Task task : tasks) {
					Map<U64, Map<String, OFStatistic>> taskStats = calculateStats(task.getDatapathId(), task);
					
					if (dpid == null)
						dpid = task.getDatapathId();
					
					for (U64 cookie : taskStats.keySet()) {
						if (!stats.containsKey(cookie))
							stats.put(cookie, new HashMap<String, OFStatistic>());
						stats.get(cookie).putAll(taskStats.get(cookie));
						
						historyStats.get(task.getDatapathId()).putAll(taskStats.get(cookie));
					}
				}
				
				for (U64 cookie : stats.keySet()) {
					logger.info("Experiment - Event - Dispatch Statistic: {}",
							String.format("![%s] ![%s] ![%d]", dpid.toString(), cookie.toString(),
									System.currentTimeMillis()));
					
					IRadarListener l = radarListeners.get(cookie);
					l.statisticUpdated(new UpdateEvent(dpid, System.currentTimeMillis(), stats.get(cookie)));
				}
			}
		}
		
		private void activeCollectionThread() throws InterruptedException {
			long now, minWait;
			
			while(true) {
				now = System.currentTimeMillis();
				minWait = minInterval;
				List<DatapathId> criticalSwitches = new ArrayList<DatapathId>();
				
				synchronized(trace) {
					for (DatapathId dpid : trace.getActivatedDetection().keySet()) {
						long past = now - trace.getLatestTime(dpid);
						if (past >= minInterval) {
							if (trace.isInProgress(dpid) == false) {
								criticalSwitches.add(dpid);
							}
						} else if (minWait > minInterval - past)
							minWait = minInterval - past;
					}
				
					for (DatapathId dpid : criticalSwitches) {
						// Experiment
						logger.info("Experiment - Event - Active Collection: {}",
							String.format("![%s] ![%d]",
									dpid.toString(), System.currentTimeMillis()));
						
						addCollectionRequest(dpid);
					}
				}
				
				Thread.sleep(minWait);
			}
		}
		
		public void triggerInMessageReceive(DatapathId dpid) {
			synchronized (trace) {
				if (trace.isInProgress(dpid) || trace.isActivated(dpid))
					return;
				if (trace.containsTrace(dpid))
					if (System.currentTimeMillis() - trace.getLatestTime(dpid) <= minInterval)
						return;
				
				// Experiment
				logger.info("Experiment - Event - Trigger-In Collection: {}",
						String.format("![%s] ![%d]", dpid.toString(), System.currentTimeMillis()));
				addCollectionRequest(dpid);
				trace.setInProgress(dpid, true);
			}
		}
		
		private void addCollectionRequest(DatapathId dpid) {
			logger.info("Experiment - Control - Add Collection Requests: {}",
					String.format("![%s] ![%d]", dpid.toString(), System.currentTimeMillis()));
			
			int types = 0;
			for (U64 vectorId : switchDetectionVectors.get(dpid))
				types |= detectionVectors.get(vectorId).getStatType();
			
			List<TaskType> taskTypes = new ArrayList<TaskType>();
			if ((types & DetectionVectorDescriptor.FLOW_STATISTIC) != 0)
				taskTypes.add(TaskType.COL_FLOW_STATS);
			if ((types & DetectionVectorDescriptor.PORT_STATISTIC) != 0)
				taskTypes.add(TaskType.COL_PORT_STATS);
			
			if (taskTypes.size() > 0)
				transactionManager.addJob(dpid, taskTypes);
		}
		
		protected Map<U64, Map<String, OFStatistic>> calculateStats(DatapathId dpid, Task task) {
			Map<U64, Map<String, OFStatistic>> stats = new HashMap<U64, Map<String, OFStatistic>>();
			List<U64> vectorIds = switchDetectionVectors.get(dpid);
			
			switch (task.getType()) {
			case COL_PORT_STATS:
				for (OFMessage reply : task.getReplies()) {
				    OFPortStatsReply value = (OFPortStatsReply)reply;
					for (OFPortStatsEntry e : value.getEntries()) {
						OFSwitchPort swPort = new OFSwitchPort(dpid, e.getPortNo().getPortNumber());
						
						long rxPackets = e.getRxPackets().getValue();
						long txPackets = e.getTxPackets().getValue();
						long packets   = rxPackets + txPackets;
						
						long rxBytes = e.getRxBytes().getValue();
						long txBytes = e.getTxBytes().getValue();
						long bytes   = rxBytes + txBytes;
						
						long now  = System.currentTimeMillis();
						
				    	double rxSpeed = 0.0;
				    	double txSpeed = 0.0;
				    	double speed   = 0.0;
				    	
				    	long rxDropped = e.getRxDropped().getValue();
				    	long txDropped = e.getTxDropped().getValue();
				    	double txLossRate = 1.0;
							
						String key = swPort.toString();
							
						Map<String, OFStatistic> swStats = historyStats.get(dpid);
						if (swStats.containsKey(key)) {
							PortStatistic oldStat = (PortStatistic)swStats.get(key);
							
							rxSpeed = (rxBytes-oldStat.getRxBytes())
									/(double)(now-oldStat.getTimeStamp())*0.008;
							txSpeed = (txBytes-oldStat.getTxBytes())
									/(double)(now-oldStat.getTimeStamp())*0.008;
							speed   = (bytes-oldStat.getBytes())
				    				/(double)(now-oldStat.getTimeStamp())*0.008;
							
							if (txPackets + e.getTxDropped().getValue()	- oldStat.getTxPackets() - oldStat.getTxDropped() != 0)
								txLossRate = (txPackets - oldStat.getTxPackets())
										/(double)(txPackets + e.getTxDropped().getValue()
												- oldStat.getTxPackets() - oldStat.getTxDropped());
						}
						
						logger.debug("Debug - Statistic - Port Statistics: {}",
								String.format("![%s] ![%d] ![%d] ![%d] ![%d] ![%f] ![%f] ![%d] ![%d] ![%f] [!%d]",
										swPort.toString(), packets, rxPackets, bytes, rxBytes,
										speed, rxSpeed, rxDropped, txDropped, txLossRate, now));
						
						for (U64 vectorId : vectorIds) {
							DetectionVectorDescriptor vector = detectionVectors.get(vectorId);
							
							if ((vector.getStatType() & DetectionVectorDescriptor.PORT_STATISTIC) != 0) {
								U64 cookie = vectorId.applyMask(cookieMask);
								if (!stats.containsKey(cookie))
									stats.put(cookie, new HashMap<String, OFStatistic>());
								
								stats.get(cookie).put(key, new PortStatistic(dpid, packets, bytes, speed, now,
										swPort, rxPackets, txPackets, rxBytes, txBytes, rxSpeed, txSpeed,
										rxDropped, txDropped, txLossRate));
							}
						}
					}
				}
				break;
				
			case COL_FLOW_STATS:
				for (OFMessage reply : task.getReplies()) {
				    OFFlowStatsReply value = (OFFlowStatsReply)reply;
					for (OFFlowStatsEntry e : value.getEntries()) {
						U64    vId     = e.getCookie();
						
						long   packets = e.getPacketCount().getValue();
						long   bytes   = e.getByteCount().getValue();
						Match  match   = e.getMatch();
						long   now     = System.currentTimeMillis();
						
				    	double speed = 0.0;
						
						if (detectionVectors.containsKey(vId)) {
//							String key = vId.toString();
//							
//							Map<String, OFStatistic> swStats = historyStats.get(dpid);
//							if (swStats.containsKey(key)) {
//								OFStatistic oldStat = swStats.get(key);
//								
//								speed         = ((double)bytes-oldStat.getBytes())
//				    					/(now-oldStat.getTimeStamp())*0.008;
//							}
//							logger.debug("Debug - Statistic - Detection Flow Statistics: {}",
//									String.format("![%s] ![%d] ![%d] ![%f]",
//											dpid.toString(), packets, bytes, speed));
//							
//							stats.put(key, new FlowStatistic(vId, dpid, packets, bytes,
//									speed, now, IPv4Address.of("0.0.0.0"), 0));

							String key;
							IPv4Address address;
							int prefix;
							
							DetectionVectorDescriptor vector = detectionVectors.get(vId);
							if (vector.isSourceLocation()) {
								address = match.get(MatchField.IPV4_SRC);
								if (address == null) {
									address = IPv4Address.of("0.0.0.0");
									prefix  = 0;
								} else if (match.isPartiallyMasked(MatchField.IPV4_SRC))
									prefix = match.getMasked(MatchField.IPV4_SRC).getMask().asCidrMaskLength();
								else
									prefix = 32;
							}
							else {
								address = match.get(MatchField.IPV4_DST);
								if (address == null) {
									address = IPv4Address.of("0.0.0.0");
									prefix  = 0;
								} else if (match.isPartiallyMasked(MatchField.IPV4_DST))
									prefix = match.getMasked(MatchField.IPV4_DST).getMask().asCidrMaskLength();
								else
									prefix = 32;
							}
							
							key = String.format("%s-%s/%d", vId.toString(), address.toString(), prefix);
							
							Map<String, OFStatistic> swStats = historyStats.get(dpid);
							if (swStats.containsKey(key)) {
								FlowStatistic oldStat = (FlowStatistic)swStats.get(key);
								
					    		speed    = ((double)bytes-oldStat.getBytes())
					    				/(now-oldStat.getTimeStamp())*0.008;
					    		
//					    		logger.info("Debug - Statistic - History Flow Statistics: {}",
//										String.format("![%s] ![%s-%d] ![%s] ![%s] ![%d] ![%d] ![%f] ![%d]",
//												key, oldStat.getDpid().toString(), e.getMatch().get(MatchField.IN_PORT).getPortNumber(),
//												oldStat.getVectorId().toString(), oldStat.getAddress().toString(), 
//												oldStat.getPackets(), oldStat.getBytes(), oldStat.getSpeed(), oldStat.getTimeStamp()));
							}
							
							U64 cookie = vId.applyMask(cookieMask);
							if (!stats.containsKey(cookie))
								stats.put(cookie, new HashMap<String, OFStatistic>());
							
							stats.get(cookie).put(key, new FlowStatistic(vId, dpid, packets,
									bytes,	speed, now, address, prefix));
							
//							logger.debug("Debug - Statistic - Detection Flow Statistics: {}",
//									String.format("![%s] ![%s-%d] ![%s] ![%s/%d] ![%d] ![%d] ![%f] ![%d]",
//											key, dpid.toString(), e.getMatch().get(MatchField.IN_PORT).getPortNumber(),
//											vId.toString(), address.toString(), prefix,	packets, bytes,	speed, now));
						}
					}
				}
				break;
				
			default:
				break;
			}
			
			return stats;
		}
		
		protected class TransactionManager extends Thread {
			private BlockingQueue<Task> replies;
			private Map<DatapathId, List<TaskType>> jobs;
			private Map<DatapathId, List<Task>> tasks;
			
			private Lock jobsLock;
			
			public TransactionManager() {
				replies = new LinkedBlockingQueue<Task>();
				jobs    = new HashMap<DatapathId, List<TaskType>>();
				tasks   = new HashMap<DatapathId, List<Task>>();
				
				jobsLock  = new ReentrantLock();
			}
			
			public void addJob(DatapathId dpid, List<TaskType> taskTypes) {
				synchronized (trace) {
					trace.setInProgress(dpid, true);
				}
				
				logger.debug("Debug - Task - Add Collection Job: {}",
						String.format("![%s] ![%s] ![%d]",
								dpid.toString(), taskTypes.toString(), System.currentTimeMillis()));
				
				jobsLock.lock(); {
					if (!jobs.containsKey(dpid))
						jobs.put(dpid, new ArrayList<TaskType>());
					jobs.get(dpid).addAll(taskTypes);
				} jobsLock.unlock();
				
				for (TaskType taskType : taskTypes) {
					switch (taskType) {
					case COL_PORT_STATS:
						addPortCollectionRequest(dpid, replies);
						break;
					case COL_FLOW_STATS:
						addFlowCollectionRequest(dpid, replies);
						break;
					default:
						taskTypes.remove(taskType);
						break;
					}
				}
			}
			
			@Override
			public void run() {
				Task task;
				while (true) {
					try {
						task = replies.take();
					} catch (InterruptedException e) {
						logger.error("Error - Job - Get Replied Task:", e);
						continue;
					}
					
					DatapathId dpid = task.getDatapathId();
					TaskType type   = task.getType();
					boolean empty;
					
					if (!tasks.containsKey(dpid))
						tasks.put(dpid, new ArrayList<Task>());
					List<Task> swTasks = tasks.get(dpid);
					swTasks.add(task);
					
					jobsLock.lock(); {
						List<TaskType> detJobs = jobs.get(dpid);
						detJobs.remove(type);
						
						empty = detJobs.isEmpty();
					} jobsLock.unlock();
					
					if (empty) {
						List<Task> res = tasks.get(dpid);
						tasks.remove(dpid);
						try {
							repliesQueue.put(res);
						} catch (InterruptedException e) {
							logger.error("Error - Job - Put Job to Queue:", e);
						}
						
						logger.debug("Debug - Task - Retrieve Job: {}",
								String.format("![%s] ![%d]",
										dpid.toString(), System.currentTimeMillis()));
						
						synchronized (trace) {
							trace.setInProgress(dpid, false);
							trace.setLatestTime(dpid, System.currentTimeMillis());
						}
					}
				}
			}
		}
	}
	
	protected class Locator {
		
		public Locator() {}
		
		// Switch flow entry control
		public void split(U64 vectorId, DatapathId dpid, List<IPv4AddressWithMask> splitted, List<IPv4AddressWithMask> merged) {
			logger.info("Experiment - Control - Split And Merge Mechanism: {}",
					String.format("![%s] ![%s] ![%d] ![%d] ![%d]", vectorId.toString(), dpid.toString(),
							splitted.size(), merged.size(), System.currentTimeMillis()));
			
			if (merged.size() != 0) {
				delLocationRules(vectorId, dpid, merged);
				for (IPv4AddressWithMask address : merged)
					historyStats.get(dpid).remove(String.format("%s-%s/%d",
							vectorId.toString(), address.getValue().toString(), address.getMask().asCidrMaskLength()));
			}
			
			if (splitted.size() != 0) {
				addLocationRules(vectorId, dpid, splitted);
				long now = System.currentTimeMillis();
				for (IPv4AddressWithMask address : splitted)
					historyStats.get(dpid).put(String.format("%s-%s/%d",
							vectorId.toString(), address.getValue().toString(), address.getMask().asCidrMaskLength()),
							new FlowStatistic(vectorId, dpid, 0, 0, 0.0, now, address.getValue(),
									address.getMask().asCidrMaskLength()));
			}
		}
	}
	
	protected class Scheduler {
		protected int maxWorker;
		
		// Basic data structures
		private Map<DatapathId, Domain>  switchDomainMapping;
		
		private BlockingQueue<Domain> waitingDomains;
		private BlockingQueue<Worker> waitingWorkers;
		
		private List<Worker> workers;
		
		private Thread assign;
		
		public Scheduler(int maxWorker) {
			this.maxWorker = maxWorker;
			
			switchDomainMapping = new HashMap<DatapathId, Domain>();
			
			waitingDomains = new LinkedBlockingQueue<Domain>();
			waitingWorkers = new LinkedBlockingQueue<Worker>();
			
			workers = new ArrayList<Worker>();
			
			assign = new Thread(new Runnable() {
				@Override
				public void run() {
					while (true) {
						try {
							assignThread();
						} catch (InterruptedException e) {
							return;
						}
					}
				}
			}, "Assign");
			assign.start();
		}
		
		protected void assignThread() throws InterruptedException {
			Domain domain;
			Worker worker;
			while (true) {
				
				domain = waitingDomains.take();
				worker = waitingWorkers.take();
				
				synchronized (domain) {
					domain.setState(Domain.STATE_ASSIGNED);
					worker.feedTask(domain.getTask());
				}
				
				logger.debug("Debug - Task - Assign: {}", String.format("![%d] ![%s] ![%d]",
						worker.getWorkerId(), domain.getDpid().toString(), System.currentTimeMillis()));
			}
		}
		
		protected class Worker extends Thread {
			private int workerId;
			private BlockingQueue<Task> taskQueue;
			
			public Worker(int workerId) {
				this.workerId  = workerId;
				this.taskQueue = new LinkedBlockingQueue<Task>();
			}
			
			public int getWorkerId() {
				return workerId;
			}
			
			public void feedTask(Task task) {
				try {
					taskQueue.put(task);
				} catch (InterruptedException e) {
					logger.error("Error - Task - Feed Task:", e);
				}
			}
			
			@Override
			public void run() {
				Task task;
				while (true) {
					try {
						task = taskQueue.take();
					} catch (InterruptedException e) {
						logger.error("Error - Task - Get Task:", e);
						continue;
					}
					
					switch (task.getType()) {
					case ADD_FLOW_RULE:
						excuteAddFlowTask(task);
						break;
					case DEL_FLOW_RULE:
						excuteDelFlowTask(task);
						break;
					case MOD_FLOW_RULE:
						excuteModFlowTask(task);
						break;
					case ADD_GROUP_TBL:
						excuteAddGroupTask(task);
						break;
					case DEL_GROUP_TBL:
						excuteDelGroupTask(task);
						break;
					case MOD_GROUP_TBL:
						excuteModGroupTask(task);
						break;
					case COL_PORT_STATS:
						excutePortStatsRequestTask(task);
						break;
					case COL_FLOW_STATS:
						excuteFlowStatsRequestTask(task);
						break;
					default:
						break;
					}
					
					waitForTask(this, task.getDatapathId());
				}
			}
			
			private void excuteAddFlowTask(Task task) {
				logger.info("Debug - Request - Add Flow Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteDelFlowTask(Task task) {
				logger.info("Debug - Request - Delete Flow Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteModFlowTask(Task task) {
				logger.info("Debug - Request - Modify Flow Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteAddGroupTask(Task task) {
				logger.info("Debug - Request - Add Group Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteDelGroupTask(Task task) {
				logger.info("Debug - Request - Delete Group Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteModGroupTask(Task task) {
				logger.info("Debug - Request - Modify Group Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteFlowTask(task);
			}
			
			private void excuteFlowTask(Task task) {
				IOFSwitch sw = switchService.getSwitch(task.getDatapathId());
				sw.write(task.getOFMessage());
				sw.flush();
			}
			
			private void excutePortStatsRequestTask(Task task) {
				logger.info("Debug - Request - Port Statistic Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteStatsRequestTask(task);
			}
			
			private void excuteFlowStatsRequestTask(Task task) {
				logger.info("Debug - Request - Flow Statistic Requests: {}",
						String.format("![%s] ![%d]", task.getDatapathId().toString(), System.currentTimeMillis()));
				
				excuteStatsRequestTask(task);
			}
			
			@SuppressWarnings({ "rawtypes", "unchecked" })
			private void excuteStatsRequestTask(Task task) {
				DatapathId dpid = task.getDatapathId();
				
				IOFSwitch sw = switchService.getSwitch(dpid);
				
				OFStatsRequest request = (OFStatsRequest)task.getOFMessage();
				
				ListenableFuture<?> future;
				List<OFMessage> values;
				
				try {
					future = sw.writeStatsRequest(request);
					values = (List<OFMessage>) future.get(timeout, timeUnit);
				} catch (Exception e) {
					logger.error("Error - Request - Retrieve Statistics:", e);
					return;
				}
				
				
				task.setReplies(values);
				try {
					task.getOutputQueue().put(task);
				} catch (InterruptedException e) {
					logger.error("Error - Request - Put Output Queue:", e);
				}
			}
		}
		
		private class PriorityTaskQueue {
			private DatapathId dpid;
			private List<Queue<Task>> taskQueues;
			private int level;
			
			public PriorityTaskQueue(DatapathId dpid, int level) {
				this.dpid  = dpid;
				this.level = level;
				taskQueues = new ArrayList<Queue<Task>>();
				
				for (int i = 0; i < level; i ++) {
					taskQueues.add(new LinkedList<Task>());
				}
			}
			
			public DatapathId getDpid() {
				return dpid;
			}
			
			public int getLevel() {
				return level;
			}
			
			public List<Queue<Task>> getTaskQueues() {
				return taskQueues;
			}
			
			public Queue<Task> getTaskQueue(int i) {
				if (i < level)
					return taskQueues.get(i);
				return null;
			}
			
			public Task dumpHighestPriorityTask() {
				for (int i = 0; i < level; i ++) {
					Queue<Task> taskQueue = taskQueues.get(i);
					if (!taskQueue.isEmpty()) {
						return taskQueue.remove();
					}
				}
				return null;
			}
			
			public Queue<Task> dumpHighestPriorityTasks() {
				for (int i = 0; i < level; i ++) {
					Queue<Task> taskQueue = taskQueues.get(i);
					if (!taskQueue.isEmpty()) {
						taskQueues.set(i, new LinkedList<Task>());
						return taskQueue;
					}
				}
				return null;
			}
			
			public boolean isEmpty() {
				for (Queue<Task> taskQueue : taskQueues) {
					if (!taskQueue.isEmpty())
						return false;
				}
				
				return true;
			}
			
			public int getTaskNumbers() {
				int res = 0;
				for (Queue<Task> taskQueue : taskQueues)
					res += taskQueue.size();
				
				return res;
			}
		}

		protected class Domain {
			private DatapathId dpid;
			private PriorityTaskQueue priorityTaskQueues;
			private int taskNumber;
			
			private int state;
			
			public final static int STATE_IDLE     = 0;
			public final static int STATE_WAITING  = 1;
			public final static int STATE_ASSIGNED = 2;
			
			public Domain(DatapathId dpid) {
				this.dpid = dpid;
				this.priorityTaskQueues = new PriorityTaskQueue(dpid, 3);
				this.taskNumber = 0;
				
				this.state = STATE_IDLE;
			}
			
			public int getState() {
				return state;
			}

			public void setState(int state) {
				this.state = state;
			}
			
			public Task getTask() {
				Task task = priorityTaskQueues.dumpHighestPriorityTask();
				taskNumber --;
				return task;
			}
			
			public Queue<Task> getTasks() {
				Queue<Task> taskQueue = priorityTaskQueues.dumpHighestPriorityTasks();
				taskNumber -= taskQueue.size();
				return taskQueue;
			}
			
			public int getTaskNumber() {
				return priorityTaskQueues.getTaskNumbers();
			}
			
			public DatapathId getDpid() {
				return dpid;
			}
			
			public boolean isIdle() {
				return taskNumber == 0;
			}
			
			public void addTask(Task task) {
				switch (task.getType()) {
				case ADD_FLOW_RULE:
				case DEL_FLOW_RULE:
				case MOD_FLOW_RULE:
					priorityTaskQueues.getTaskQueue(2).add(task);
					break;
				case ADD_GROUP_TBL:
				case DEL_GROUP_TBL:
				case MOD_GROUP_TBL:
					priorityTaskQueues.getTaskQueue(1).add(task);
					break;
				case COL_PORT_STATS:
				case COL_FLOW_STATS:
					boolean flag = true;
					Iterator<Task> iter = priorityTaskQueues.getTaskQueue(0).iterator();
					while (iter.hasNext()) {
						Task t = iter.next();
						if (t.getType() == task.getType() && t.getDatapathId() == task.getDatapathId()) {
							flag = false;
							break;
						}
					}
					if (flag)
						priorityTaskQueues.getTaskQueue(0).add(task);
					break;
				default:
					break;
				}
				
				taskNumber ++;
			}
			
			public void addTasks(List<Task> tasks) {
				for(Task task : tasks) {
					this.addTask(task);
				}
			}
		}

		public void addTask(DatapathId dpid, Task task) {
			Domain domain = switchDomainMapping.get(dpid);
			logger.debug("Debug - Task - Add Task: {}", 
					String.format("![%s]", dpid.toString()));
			
			synchronized (domain) {
				domain.addTask(task);
				
				if (domain.getState() == Domain.STATE_IDLE)
					try {
						waitingDomains.put(domain);
						domain.setState(Domain.STATE_WAITING);
					} catch (InterruptedException e) {
						logger.error("Error - Task - Put Domain into Waiting Queue:", e);
					}
			}
				
		}

		public void addTasks(DatapathId dpid, List<Task> tasks) {
			Domain domain = switchDomainMapping.get(dpid);
			
			synchronized (domain) {
				domain.addTasks(tasks);
				logger.debug("Debug - Task - Add Tasks: {}", 
						String.format("![%s] ![%d]", dpid.toString(), tasks.size()));
				if (domain.getState() == Domain.STATE_IDLE)
					try {
						waitingDomains.put(domain);
						domain.setState(Domain.STATE_WAITING);
					} catch (InterruptedException e) {
						logger.error("Error - Task - Put Domain into Waiting Queue:", e);
					}
				
			}
		}
		
		protected void waitForTask(Worker worker, DatapathId dpid) {
			Domain domain = switchDomainMapping.get(dpid);
			
			synchronized (domain) {
				if (!domain.isIdle())
					try {
						waitingDomains.put(domain);
						domain.setState(Domain.STATE_WAITING);
					} catch (InterruptedException e) {
						logger.error("Error - Task - Put Domain into Waiting Queue:", e);
					}
				else
					domain.setState(Domain.STATE_IDLE);
			}
			
			try {
				waitingWorkers.put(worker);
			} catch (InterruptedException e) {
				logger.error("Error - Task - Put Worker into Waiting Queue:", e);
			}
		}
		
		public void addSwitch(DatapathId dpid) {
			logger.debug("Debug - Task - Add Domain: {}", 
					String.format("![%s]", dpid.toString()));
			
			Domain domain = new Domain(dpid);
			
			switchDomainMapping.put(dpid, domain);
			
			if (workers.size() < maxWorker) {
				Worker worker = new Worker(workers.size()+1);
				worker.start();
				
				workers.add(worker);
				try {
					waitingWorkers.put(worker);
				} catch (InterruptedException e) {
					logger.error("Error - Task - Put Worker into Waiting Queue:", e);
				}
			}
		}
	}

	private void addDetectionRule(U64 vectorId, DatapathId dpid) {
		logger.debug("Debug - Task - Add Detection Rule: {}",
				String.format("![%s] ![%s]", dpid.toString(), vectorId.toString()));
		
		DetectionVectorDescriptor vector = detectionVectors.get(vectorId);
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		
		if (vector.getTriggerRate() != 0) {
			addGroupTable(dpid, groupTableAllocation.get(vectorId), vector.getTriggerRate(), true);
			
			// Prepare goto-group action
			OFActionGroup gotoGroup = sw.getOFFactory().actions()
					.group(OFGroup.of(groupTableAllocation.get(vectorId)));
			List<OFAction> actions = new ArrayList<OFAction>();
			actions.add(gotoGroup);
			
			OFInstruction applyActions = sw.getOFFactory().instructions()
					.applyActions(actions);
			instructions.add(applyActions);
		}
		
		// Prepare goto-table instructions
		OFInstruction gotoTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(detectionTableAllocation.get(vectorId) + 1));
		instructions.add(gotoTable);
		
		// Prepare match fields
		Match match = MatchUtils.fromString(vector.toString(), sw.getOFFactory().getVersion());
		
		// Prepare flowadd message
		OFFlowAdd addDetRule = sw.getOFFactory().buildFlowAdd()
				.setCookie(vectorId)
				.setTableId(TableId.of(detectionTableAllocation.get(vectorId)))
				.setPriority(detectionPriority)
				.setMatch(match)
				.setInstructions(instructions)
				.build();
		
		scheduler.addTask(dpid, new Task(TaskType.ADD_FLOW_RULE, dpid, addDetRule));
	}
	
	private void addLocationRules(U64 vectorId, DatapathId dpid, List<IPv4AddressWithMask> addresses) {
		DetectionVectorDescriptor vector = detectionVectors.get(vectorId);
		List<Task> tasks = new ArrayList<Task>();
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		// Prepare instructions
		OFInstruction gotoTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(detectionTableAllocation.get(vectorId) + 1));
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(gotoTable);
		
		for (IPv4AddressWithMask address : addresses) {
			logger.debug("Debug - Task - Add Location Rule: {}",
					String.format("![%s] ![%s] ![%s]", dpid.toString(), vectorId.toString(), address.toString()));

			// Prepare match fields
			String matchString = vector.toString();
			if (address.getMask().asCidrMaskLength() != 0) {
				if (vector.isSourceLocation())
					matchString = matchString.concat(String.format(",%s=%s", MatchUtils.STR_NW_SRC, address.toString()));
				else
					matchString = matchString.concat(String.format(",%s=%s", MatchUtils.STR_NW_DST, address.toString()));
			}
			
			Match match = MatchUtils.fromString(matchString, sw.getOFFactory().getVersion());
			
			OFFlowAdd addLocRule = sw.getOFFactory().buildFlowAdd()
					.setCookie(vectorId)
					.setTableId(TableId.of(detectionTableAllocation.get(vectorId)))
					.setPriority(detectionPriority + address.getMask().asCidrMaskLength())
					.setMatch(match)
					.setInstructions(instructions)
					.build();
			
			tasks.add(new Task(TaskType.ADD_FLOW_RULE, dpid, addLocRule));
		}
		
		scheduler.addTasks(dpid, tasks);
	}
	
	private void delLocationRules(U64 vectorId, DatapathId dpid, List<IPv4AddressWithMask> addresses) {
		DetectionVectorDescriptor vector = detectionVectors.get(vectorId);
		List<Task> tasks = new ArrayList<Task>();
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		for (IPv4AddressWithMask address : addresses) {
			logger.debug("Debug - Task - Delete Location Rule: {}",
					String.format("![%s] ![%s] ![%s]", dpid.toString(), vectorId.toString(), address.toString()));
			
			String matchString = vector.toString();
			if (vector.isSourceLocation())
				matchString = matchString.concat(String.format(",%s=%s", MatchUtils.STR_NW_SRC, address.toString()));
			else
				matchString = matchString.concat(String.format(",%s=%s", MatchUtils.STR_NW_DST, address.toString()));
			Match match = MatchUtils.fromString(matchString, sw.getOFFactory().getVersion());
			
			OFFlowDelete delLocRule = sw.getOFFactory().buildFlowDelete()
					.setTableId(TableId.of(detectionTableAllocation.get(vectorId)))
					.setPriority(detectionPriority + address.getMask().asCidrMaskLength())
					.setMatch(match)
					.build();
			
			tasks.add(new Task(TaskType.DEL_FLOW_RULE, dpid, delLocRule));
		}
		
		scheduler.addTasks(dpid, tasks);
	}
	
	private void addFlowCollectionRequest(DatapathId dpid, BlockingQueue<Task> repliesQueue) {
		logger.debug("Debug - Task - Add Flow Statistic Request Task: {}",
				String.format("![%s]", dpid.toString()));
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFStatsRequest<?> req = sw.getOFFactory().buildFlowStatsRequest()
				.setCookie(cookieHeader)
				.setCookieMask(headerMask)
				.build();
		
		Task task = new Task(TaskType.COL_FLOW_STATS, dpid, req, repliesQueue);
		scheduler.addTask(dpid, task);
	}
	
	private void addPortCollectionRequest(DatapathId dpid, BlockingQueue<Task> repliesQueue) {
		logger.debug("Debug - Task - Add Port Statistic Request Task: {}",
				String.format("![%s]", dpid.toString()));
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFStatsRequest<?> req = sw.getOFFactory().buildPortStatsRequest()
				.setPortNo(OFPort.ANY)
				.build();
		
		Task task = new Task(TaskType.COL_PORT_STATS, dpid, req, repliesQueue);
		scheduler.addTask(dpid, task);
	}
	
	private void addDefaultGotoTblRule(DatapathId dpid, int curTblId, int gotoTblId) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFInstruction gotoTable = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(gotoTblId));
		List<OFInstruction> gotoLstTbl = new ArrayList<OFInstruction>();
		gotoLstTbl.add(gotoTable);
		
		OFFlowAdd defaultGotoTblAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(curTblId))
				.setInstructions(gotoLstTbl)
				.build();
		
		scheduler.addTask(dpid, new Task(TaskType.ADD_FLOW_RULE, dpid, defaultGotoTblAdd));
	}
	
	private void addGroupTable(DatapathId dpid, int groupId, int triggerRate, boolean isNew) {
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFActionDecNwTtl decTTL = sw.getOFFactory().actions().decNwTtl();
		OFActionOutput gotoController = sw.getOFFactory().actions().buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER)
				.build();
		
		List<OFAction> actions1 = new ArrayList<OFAction>();
		actions1.add(decTTL);
		actions1.add(gotoController);
		
		List<OFAction> actions2 = new ArrayList<OFAction>();
		actions2.add(decTTL);
		
		OFBucket bucket1 = sw.getOFFactory().buildBucket()
				.setWatchGroup(OFGroup.ANY)
				.setWatchPort(OFPort.ANY)
				.setWeight(1)
				.setActions(actions1)
				.build();
		
		int rate = triggerRate - 1;
		if (triggerRate == 0)
			rate = 1;
		
		OFBucket bucket2 = sw.getOFFactory().buildBucket()
				.setWatchGroup(OFGroup.ANY)
				.setWatchPort(OFPort.ANY)
				.setWeight(rate)
				.setActions(actions2)
				.build();

		List<OFBucket> buckets = new ArrayList<OFBucket>();
		buckets.add(bucket1);
		if (triggerRate != 0)
			buckets.add(bucket2);
		
		if (isNew) {
			OFGroupAdd groupAdd = sw.getOFFactory().buildGroupAdd()
					.setGroup(OFGroup.of(groupId))
					.setGroupType(OFGroupType.SELECT)
					.setBuckets(buckets)
					.build();
			
			scheduler.addTask(dpid, new Task(TaskType.ADD_GROUP_TBL, dpid, groupAdd));
		} else {
			OFGroupMod groupMod = sw.getOFFactory().buildGroupModify()
					.setGroup(OFGroup.of(groupId))
					.setGroupType(OFGroupType.SELECT)
					.setBuckets(buckets)
					.build();
			
			scheduler.addTask(dpid, new Task(TaskType.MOD_GROUP_TBL, dpid, groupMod));
		}
	}
	
	// Packet-In message handler
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() == OFType.PACKET_IN) {
			OFPacketIn pktin = (OFPacketIn)msg;
			
			if (pktin.getCookie().applyMask(headerMask).equals(cookieHeader))
				collector.triggerInMessageReceive(sw.getId());
		}
		
		return Command.CONTINUE;
	}
	
	private class Trace {
		private Map<DatapathId, List<U64>> activated;
		private Map<DatapathId, Boolean> inProgress;
		private Map<DatapathId, Long>    latestTime;
		
		public Trace() {
			activated  = new HashMap<DatapathId, List<U64>>();
			inProgress = new HashMap<DatapathId, Boolean>();
			latestTime = new HashMap<DatapathId, Long>();
		}
		
		public boolean containsTrace(DatapathId dpid) {
			if (latestTime.containsKey(dpid))
				return true;
			return false;
		}
		
		public boolean isInProgress(DatapathId dpid) {
			if (inProgress.containsKey(dpid))
				return inProgress.get(dpid);
			return false;
		}
		
		public boolean isActivated(DatapathId dpid) {
			if (activated.containsKey(dpid))
				return activated.get(dpid).size() > 0;
			return false;
		}
		
		public Map<DatapathId, List<U64>> getActivatedDetection() {
			return activated;
		}
		
		public long getLatestTime(DatapathId dpid) {
			return latestTime.get(dpid);
		}
		
		public void setInProgress(DatapathId dpid, boolean isInProgress) {
			inProgress.put(dpid, isInProgress);
		}
		
		public void setActivated(DatapathId dpid, U64 vectorId, boolean isActivated) {
			if (!activated.containsKey(dpid))
				activated.put(dpid, new ArrayList<U64>());
			
			if (isActivated) {
				if (!activated.get(dpid).contains(vectorId))
					activated.get(dpid).add(vectorId);
			} else {
				if (!activated.get(dpid).contains(vectorId))
					activated.get(dpid).remove(vectorId);
			}
		}			
		
		public void setLatestTime(DatapathId dpid, long latest) {
			latestTime.put(dpid, latest);
		}
	}
	
	// Initialize flow tables
	private void initDefaultRules(DatapathId dpid) {
		IOFSwitch sw = switchService.getSwitch(dpid);
				
		// Clear all rules.
		OFFlowDelete flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.ALL)
				.setCookie(cookieHeader)
				.setCookieMask(headerMask)
				.build();
		sw.write(flowdel);
		sw.flush();
		
		// Clear all groups.
		OFGroupDelete groupDel = sw.getOFFactory().buildGroupDelete()
				.setGroup(OFGroup.ALL)
				.setGroupType(OFGroupType.SELECT)
				.build();
		sw.write(groupDel);

		addDefaultGotoTblRule(dpid, firstDetectionTbl, firstForwardingTbl);
		
		// Add packet-in rule for forwarding-table
		OFAction gotoController = sw.getOFFactory().actions().buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER)
				.build();
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(gotoController);
		
		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(basicPriority)
				.setTableId(TableId.of(firstForwardingTbl))
				.setMatch(
						sw.getOFFactory().buildMatch().build())
				.setActions(actions)
				.build();
		
		scheduler.addTask(dpid, new Task(TaskType.ADD_FLOW_RULE, dpid, flowAdd));
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		logger.info("Experiment - Event - Add Switch: {}",
				String.format("![%s] ![%d]", switchId.toString(), System.currentTimeMillis()));
		
		scheduler.addSwitch(switchId);
		initDefaultRules(switchId);
		
		historyStats.put(switchId, new HashMap<String, OFStatistic>());
		
		currentDetectionTbl.put(switchId, firstDetectionTbl);
		currentGroupTbl.put(switchId, 1);
		
		switchDetectionVectors.put(switchId, new ArrayList<U64>());
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
		
		// Logger
		logger = LoggerFactory.getLogger(RadarManagerHW.class);
		
		// Initialize basic classes
		trace     = new Trace();
		collector = new Collector();
		locator   = new Locator();
		scheduler = new Scheduler(numWorker);
		
		detectorNames  = new HashMap<U64, String>();
		radarListeners = new HashMap<U64, IRadarListener>();
		
		configurations = new HashMap<U64, RadarConfiguration>();
		
		historyStats = new HashMap<DatapathId, Map<String, OFStatistic>>();
		
		detectionVectors = new HashMap<U64, DetectionVectorDescriptor>();
		switchDetectionVectors = new HashMap<DatapathId, List<U64>>();
		
		currentDetectionTbl = new HashMap<DatapathId, Integer>();
		currentGroupTbl     = new HashMap<DatapathId, Integer>();
		
		detectionTableAllocation = new HashMap<U64, Integer>();
		groupTableAllocation = new HashMap<U64, Integer>();
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
		return RadarManagerHW.class.getSimpleName();
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
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IRadarService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m
			= new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IRadarService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IOFSwitchService.class);
		return l;
	}
}
