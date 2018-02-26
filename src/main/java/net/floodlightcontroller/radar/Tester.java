package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.ReadLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.projectfloodlight.openflow.protocol.OFBucket;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest;
import org.projectfloodlight.openflow.protocol.OFGroupAdd;
import org.projectfloodlight.openflow.protocol.OFGroupDelete;
import org.projectfloodlight.openflow.protocol.OFGroupType;
import org.projectfloodlight.openflow.protocol.OFMatchV3;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFPortStatsEntry;
import org.projectfloodlight.openflow.protocol.OFPortStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
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
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
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
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;

public class Tester implements IOFMessageListener, IOFSwitchListener, IFloodlightModule {

	// Services
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService           switchService;
	
	// Packet-In message handler threads control
	
	
//	protected List<BlockingQueue<Task>> taskQueues;
//	protected List<Lock>                taskLocks;
//	protected List<Condition>           conditions;
	
//	protected BlockingQueue<Task> priorTaskQueue;
//	protected BlockingQueue<Task> inferiorTaskQueue;
	
	protected List<DatapathId> switches;
//	protected List<Worker>     workers;
	protected Scheduler        scheduler;
	protected Thread           activeCollectionTask;
	
	protected Map<DatapathId, List<Integer>> portCollectionRecord;
	protected Map<DatapathId, Integer>       flowCollectionRecord;
	
	protected Map<DatapathId, List<IPv4Address>> latestAddress;
	protected double power;
	
	// Packet-In message handler threads control parameters
	protected static final int      numWorker  = 16;
	protected static final int      timeout    = 1000;
	protected static final TimeUnit timeUnit   = TimeUnit.MILLISECONDS;
	
	protected ReentrantReadWriteLock         portStatsLock;
	protected ReadLock                       readPortStatsLock;
	protected WriteLock                      writePortStatsLock;
	
	protected ReentrantReadWriteLock         flowsStatsLock;
	protected ReadLock                       readFlowsStatsLock;
	protected WriteLock                      writeFlowsStatsLock;
	
	protected HashMap<DatapathId, HashMap<String, OFStatistic>> flowsStats;
	
	protected long minInterval = 1000;
	
	protected static final int flowMonitorTbl = 0;
	protected static final int linkMonitorTbl = 1;
	protected static final int forwardingTbl  = 2;

	protected static final int zeroPriority          = 0;
	protected static final int basicMonitorPriority  = 10;
	protected static final int arpPriority           = 50;
	protected static final int blockPriority         = 60;

	// Logger
	protected static Logger logger;
	
	// Task types
	public enum TaskType {
		PORT_STATISTICS_COLLECTION,
		FLOW_STATISTICS_COLLECTION,
		ADD_COLLECTION_RULE,
		DEL_COLLECTION_RULE,
		BLOCK_COLLECTION_RULE,
		ADJUST_RATIO
	}
	
	public void splitCollectRules(DatapathId dpid, IPv4Address ip, int exp,
			int newExp) {
		
		int i = 0;
		int d = (int)Math.pow(2, 32-newExp);
		int l = (int)Math.pow(2, newExp-exp);
		
		int iterIP = ip.getInt();
		
		List<Task> tasks = new ArrayList<Task>();
		while (i < l) {
			tasks.add(new Task(dpid.toString(), TaskType.ADD_COLLECTION_RULE,
					dpid, IPv4Address.of(iterIP), newExp));
			iterIP += d;
			i ++;
		}
		
		scheduler.addTasks(dpid, TaskType.ADD_COLLECTION_RULE, tasks);
	}

	public void mergeCollectRules(DatapathId dpid, IPv4Address ip, int exp,
			int newExp) {
		
		int i = 0;
		int d = (int)Math.pow(2, 32-exp);
		int l = (int)Math.pow(2, exp-newExp);
		
		int iterIP = ip.getInt();
		
		List<Task> tasks = new ArrayList<Task>();
		while (i < l) {
			tasks.add(new Task(dpid.toString(), TaskType.DEL_COLLECTION_RULE,
					dpid, IPv4Address.of(iterIP), exp));
			iterIP += d;
			i ++;
		}
		
		scheduler.addTasks(dpid, TaskType.DEL_COLLECTION_RULE, tasks);
	}
	
	public void addCollectRule(DatapathId dpid, IPv4Address ip, int exp) {
		// Experiment
//		synchronized(addFlowRequests) {
//			logger.info("Experiment - Request - Add Flow Requests: {}",
//					String.format("%s ![%d] ![%d]", dpid.toString(), ++ addFlowRequests, System.currentTimeMillis()));
//		}
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		Match match = sw.getOFFactory().buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setMasked(MatchField.IPV4_SRC, ip, IPv4Address.ofCidrMaskLength(exp))
				.build();
		
		OFInstruction goto_tbl = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(forwardingTbl));
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(goto_tbl);
		
		// TODO: Priority Thread
		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
				.setTableId(TableId.of(flowMonitorTbl))
				.setPriority(basicMonitorPriority + exp)
				.setMatch(match)
				.setInstructions(instructions)
				.build();
		
//		requestLock.lock();
//		while (true) {
//			synchronized(numRequests) {
//				if (numRequests == 0)
//					break;
//			}
//			
//			try {
//				allowed.await();
//			} catch (InterruptedException e) {
//				e.printStackTrace();
//			}
//		}

		sw.write(flowAdd);
		sw.flush();
//		requestLock.unlock();
	}
	
	public void delCollectRule(DatapathId dpid, IPv4Address ip, int exp) {
		// Experiment
//		synchronized(delFlowRequests) {
//			logger.info("Experiment - Request - Delete Flow Requests: {}",
//					String.format("%s ![%d] ![%d]", dpid.toString(), ++ delFlowRequests, System.currentTimeMillis()));
//		}
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		Match match = sw.getOFFactory().buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setMasked(MatchField.IPV4_SRC, ip, IPv4Address.ofCidrMaskLength(exp))
				.build();
		
		OFInstruction goto_tbl = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(linkMonitorTbl));
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(goto_tbl);
		
		// TODO: Priority Thread
		OFFlowDelete flowDel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.of(flowMonitorTbl))
				.setPriority(basicMonitorPriority + exp)
				.setMatch(match)
				.setInstructions(instructions)
				.build();
		
//		requestLock.lock();
//		while (true) {
//			synchronized(numRequests) {
//				if (numRequests == 0)
//					break;
//			}
//			
//			try {
//				allowed.await();
//			} catch (InterruptedException e) {
//				e.printStackTrace();
//			}
//		}

		sw.write(flowDel);
		sw.flush();
//		requestLock.unlock();
	}
	
	// Packet-In message handler
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		return Command.CONTINUE;
	}
	
	// Switch statistics collection
	@SuppressWarnings("unchecked")
	protected Map<String, Object> collectPortStats(DatapathId dpid, OFPort port) {
		// Experiment
//		synchronized(portStatsRequests) {
//			logger.info("Experiment - Request - Port Statistics Requests: {}",
//					String.format("%s-%d ![%d] ![%d]", dpid.toString(), port.getPortNumber(),
//							++ portStatsRequests, System.currentTimeMillis()));
//		}
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
//		OFStatsRequest<?> req = sw.getOFFactory().buildPortStatsRequest()
//				.setPortNo(port)
//				.build();
		
		OFStatsRequest<?> req = sw.getOFFactory().buildPortStatsRequest()
				.setPortNo(OFPort.ALL)
				.build();

		ListenableFuture<?> future;
		List<OFStatsReply> values = null;
		
		try {
			if (req != null) {
//				requestLock.lock();
//				
//				synchronized(numRequests) {
//					numRequests ++;
//				}
				
				future = sw.writeStatsRequest(req);			
				values = (List<OFStatsReply>) future.get(timeout, timeUnit);
			}
		} catch (Exception e) {
			logger.error("Failure retrieving port statistics from switch: {} {}",
					String.format("%s-%d", sw.getId().toString(), port.getPortNumber()), e.toString());
		} finally {
//			synchronized(numRequests) {
//				numRequests --;
//				if (numRequests == 0)
//					allowed.signalAll();
//			}
//			
//			requestLock.unlock();
		}
		
		if(values == null)
			return null;
		
		for (OFStatsReply value : values) {
			OFPortStatsReply reply = (OFPortStatsReply)value;
			for (OFPortStatsEntry e : reply.getEntries()) {
				String key           = String.format("%s-%d", dpid.toString(), port.getPortNumber());
				long   packets       = e.getRxPackets().add(e.getTxPackets()).getValue();
				long   bytes         = e.getRxBytes().add(e.getTxBytes()).getValue();
				long   now           = System.currentTimeMillis();
			
				HashMap<String, Object> result = new HashMap<String, Object>();
				result.put("key"      , key);
				result.put("dpid"     , dpid);
				result.put("port"     , port);
				result.put("packets"  , packets);
				result.put("bytes"    , bytes);
				result.put("timestamp", now);
				
				return result;
			}
		}
		
		return null;
	}
	
	@SuppressWarnings("unchecked")
	protected Map<String, Map<String, Object>> collectFlowsStats(DatapathId dpid) {
		// Experiment
//		synchronized(flowsStatsRequests) {
//			logger.info("Experiment - Request - Flows Statistics Requests: {}",
//					String.format("%s ![%d] ![%d]", dpid.toString(), ++ flowsStatsRequests, System.currentTimeMillis()));
//		}
		
		IOFSwitch sw = switchService.getSwitch(dpid);
		
		OFFlowStatsRequest req = sw.getOFFactory().buildFlowStatsRequest()
			.setMatch(
					sw.getOFFactory().buildMatch().build()
					)
			.setTableId(TableId.of(flowMonitorTbl))
			.build();
		
		ListenableFuture<?> future;
		List<OFStatsReply> values = null;
		
//		logger.info("Request for Flow Statistics: {} {}", sw.getId(), System.currentTimeMillis());
		try {
			if (req != null) {
//				requestLock.lock();
//				
//				synchronized(numRequests) {
//					numRequests ++;
//				}
				
				future = sw.writeStatsRequest(req);			
				values = (List<OFStatsReply>) future.get(timeout, timeUnit);
			}
		} catch (Exception e) {
			logger.error("Failure retrieving flows statistics from switch: {} {}", sw.getId(), e.toString());
		} finally {
//			synchronized(numRequests) {
//				numRequests --;
//				if (numRequests == 0)
//					allowed.signalAll();
//			}
//			
//			requestLock.unlock();
		}
		
		if(values == null)
			return null;
		
		for (OFStatsReply value : values) {
			HashMap<String, Map<String, Object>> newFlowsStats = new HashMap<String, Map<String, Object>>();
		    
		    OFFlowStatsReply reply = (OFFlowStatsReply)value;
			for (OFFlowStatsEntry e : reply.getEntries()) {
				String      key;
				IPv4Address address;
				int         mask;
				long        packets;
				long        bytes;
				long        now = System.currentTimeMillis();
				
				OFMatchV3 match = (OFMatchV3)e.getMatch();
				address = match.get(MatchField.IPV4_SRC);
				if (address == null)
					continue;
				if (!match.isPartiallyMasked(MatchField.IPV4_SRC))
					continue;
				
				mask = match.getMasked(MatchField.IPV4_SRC).getMask().asCidrMaskLength();
				
				key           = String.format("%s/%d", address.toString(), mask);
				packets       = e.getPacketCount().getValue();
				bytes         = e.getByteCount().getValue();
		    	
				HashMap<String, Object> flowStats = new HashMap<String, Object>();
				flowStats.put("key", key);
				flowStats.put("dpid", dpid);
				flowStats.put("address", address);
				flowStats.put("mask", mask);
				flowStats.put("packets", packets);
				flowStats.put("bytes", bytes);
				flowStats.put("timestamp", now);
				
				newFlowsStats.put(key, flowStats);
			}
			
			return newFlowsStats;
		}
		
		return null;
	}
	
	protected void restoreFlowsStats(DatapathId dpid, HashMap<String, OFStatistic> newFlowsStats) {
		if (newFlowsStats != null) {
			writeFlowsStatsLock.lock();
			flowsStats.put(dpid, newFlowsStats);
			writeFlowsStatsLock.unlock();
		}
	}
	
	protected class Task {
		private String      name;
		private TaskType    type;
		private DatapathId  dpid;
		private OFPort      port;
		private IPv4Address address;
		private Integer     mask;
		
		private long timeStamp;
		
		public Task(String key, TaskType type, DatapathId dpid, OFPort port) {
			this.name    = key;
			this.type    = type;
			this.dpid    = dpid;
			this.port    = port;
			this.address = null;
			this.mask    = null;
			
			this.timeStamp = System.currentTimeMillis();
		}
		
		public Task(String key, TaskType type, DatapathId dpid, IPv4Address address, Integer mask) {
			this.name    = key;
			this.type    = type;
			this.dpid    = dpid;
			this.port    = null;
			this.address = address;
			this.mask    = mask;
			
			this.timeStamp = System.currentTimeMillis();
		}
		
		public String getTaskName() {
			return name;
		}
		
		public TaskType getType() {
			return type;
		}
		
		public DatapathId getDatapathId() {
			return dpid;
		}

		public OFPort getPort() {
			return port;
		}
		
		public long getTimeStamp() {
			return timeStamp;
		}
		
		public IPv4Address getAddress() {
			return address;
		}
		
		public Integer getMask() {
			return mask;
		}
	}
	
	protected class Worker extends Thread {
		private Scheduler scheduler;
		
		public Worker(Scheduler scheduler) {
			this.scheduler = scheduler;
		}

		@Override
		public void run() {
			Queue<Task> tasks;
			while (true) {
				tasks = scheduler.getTask(super.getName());
                
                try {
                	excuteTasks(tasks);
                } catch(Exception e) {
                	// Experiment
//    				synchronized(failedTasks) {
//    					logger.info("Experiment - Task - Failed Tasks: {}",
//    							String.format("%s ![%d] ![%d]", task.getTaskName(), ++ failedTasks, System.currentTimeMillis()));
//    				}
    				logger.error("Error - Task - Runtime Exception: {}", e.toString());
                }
                
//                synchronized(waitingTasks) {
//    				waitingTasks.remove(task.getTaskName());
//    				logger.info("Experiment - Task - Waiting Tasks: {}", taskQueue.size());	// Experiment
//    			}
                
                
                
//                logger.info("Experiment - Task - Total Time: {} {}",
//                		String.format("%s %s", task.getTaskName(), task.getType().toString()),
//                		System.currentTimeMillis() - task.getTimeStamp());	// Experiment
                
                // Experiment
//                synchronized(activeTasks) {
//                	-- activeTasks;
//                }
			}
			
		}
		
		private void excuteTasks(Queue<Task> tasks) {
			for (Task task : tasks) {
				long start = System.currentTimeMillis();	// Experiment
				
//				logger.info("Experiment - Task - Task Start  : {} {}",
//                		String.format("%s %s", task.getTaskName(), task.getType().toString()),
//                		System.currentTimeMillis() - task.getTimeStamp());	// Experiment
				
				DatapathId  dpid;
				OFPort      port;
				IPv4Address address;
				int         mask;
				switch (task.getType()) {
				case PORT_STATISTICS_COLLECTION:
					dpid = task.getDatapathId();
					port = task.getPort();
					Map<String, Object> portStats = collectPortStats(dpid, port);
//					logger.info("Test - Retrieve Port Statistics: {}", task.getTaskName());
				
					scheduler.addTask(new Task(dpid.toString(), TaskType.FLOW_STATISTICS_COLLECTION, dpid, port));
					break;
				
				case FLOW_STATISTICS_COLLECTION:
					Map<String, Map<String, Object>> flowsStats = collectFlowsStats(task.getDatapathId());
//			    	logger.info("Test - Retrieve Flows Statistics: {}", task.getTaskName());
					break;
				
				case ADD_COLLECTION_RULE:
				
//					logger.info("Test - Split Collection Rules: {}",
//							String.format("%s %s/%d", dpid.toString(), address.toString(), mask));
				
					addCollectRule(task.getDatapathId(), task.getAddress(), task.getMask());
//					splitCollectRules(dpid, address, mask, mask+8);
				
					break;
				
				case DEL_COLLECTION_RULE:
				
//					logger.info("Test - Merge Collection Rules: {}",
//							String.format("%s %s/%d", dpid.toString(), address.toString(), mask));
				
					delCollectRule(task.getDatapathId(), task.getAddress(), task.getMask());
//					mergeCollectRules(dpid, address, mask, mask-8);
				
					break;

				case BLOCK_COLLECTION_RULE:
//					block(task.getDatapathId(), task.getAddress(), task.getMask());
					break;
				case ADJUST_RATIO:
				default:
					break;
				}
				
				if (task.getType() == TaskType.PORT_STATISTICS_COLLECTION
						|| task.getType() == TaskType.FLOW_STATISTICS_COLLECTION)
					logger.info("Experiment - Task - Working Time: {} {}",
							String.format("%s %s", task.getTaskName(), task.getType().toString()),
							System.currentTimeMillis() - start);	// Experiment
			}
		}
	}
	
	protected class Scheduler {
		private Map<String, Worker> workers;
		private Map<String, Queue<PriorityTaskQueues>> workerTaskMapping;
		private Map<DatapathId, PriorityTaskQueues> switchTaskMapping;
		
		private Map<String,     Lock> workerLocks;
		private Map<DatapathId, Lock> switchLocks;
		private Map<Lock, Condition>  conditions;
		
		private Map<String, Map<DatapathId, Integer>> workerSwitchesTasks;
		private long latestSchedule;
		
		public Scheduler(int n) {
			workers           = new HashMap<String, Worker>();
			workerTaskMapping = new HashMap<String, Queue<PriorityTaskQueues>>();
			switchTaskMapping = new HashMap<DatapathId, PriorityTaskQueues>();
			
			workerLocks = new HashMap<String, Lock>();
			switchLocks = new HashMap<DatapathId, Lock>();
			conditions  = new HashMap<Lock, Condition>();
			
			workerSwitchesTasks = new HashMap<String, Map<DatapathId, Integer>>();
			
			for (int i = 0; i < n; i ++) {
				
				Worker w = new Worker(this);
				String name = w.getName();
				
				workers.put(w.getName(), w);
				workerTaskMapping.put(name, new LinkedList<PriorityTaskQueues>());
				workerSwitchesTasks.put(name, new HashMap<DatapathId, Integer>());
				
				ReentrantLock lock = new ReentrantLock();
				workerLocks.put(name, lock);
				conditions.put(lock, lock.newCondition());
			}
			
			for (Worker w : workers.values())
				w.start();
			
//			logger.info("Tester - Scheduler - Parameters Workers: {}", workers);
		}
		
		public void addTask(Task task) {
			DatapathId dpid = task.getDatapathId();
			Lock lock;
			
			synchronized(switchLocks) {
				lock = switchLocks.get(dpid);
			}
			
			lock.lock();
			
			Queue<Task> taskQueue = null;
			switch (task.getType()) {
			case PORT_STATISTICS_COLLECTION:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(0);
				break;
			case FLOW_STATISTICS_COLLECTION:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(1);
				break;
			default:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(2);
				break;
			}
			
			if (taskQueue != null) {
				taskQueue.add(task);
				conditions.get(lock).signal();
			}
			
			lock.unlock();
			
			logger.info("Tester - Scheduler - Add Task: {} {}", dpid.toString(),
					task.getType().toString());
		}
		
		public void addTasks(DatapathId dpid, TaskType type, List<Task> tasks) {
			Lock lock;
			synchronized(switchLocks) {
				lock = switchLocks.get(dpid);
			}
			
			lock.lock();
			
			Queue<Task> taskQueue = null;
			switch (type) {
			case PORT_STATISTICS_COLLECTION:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(0);
				break;
			case FLOW_STATISTICS_COLLECTION:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(1);
				break;
			default:
				taskQueue = switchTaskMapping.get(dpid).getTaskQueue(2);
				break;
			}
			
			if (taskQueue != null) {
				taskQueue.addAll(tasks);
				conditions.get(lock).signal();
			}
			
			lock.unlock();
			
			logger.info("Tester - Scheduler - Add Tasks: {} {}", dpid.toString(), type.toString());
		}
		
		public Queue<Task> getTask(String workerId) {
			Queue<Task> tasks = null;
			Lock lock = workerLocks.get(workerId);
			
			lock.lock();
			
			while (true) {
				Queue<PriorityTaskQueues> priorityTaskQueues = workerTaskMapping.get(workerId);
				
				for (int i = 0; i < priorityTaskQueues.size(); i ++) {
					PriorityTaskQueues priorityTaskQueue = priorityTaskQueues.remove();
					List<Queue<Task>> taskQueues = priorityTaskQueue.getTaskQueues();
					for (int j = 0; j < taskQueues.size(); j ++) {
						Queue<Task> taskQueue = taskQueues.get(j);
						
						if (!taskQueue.isEmpty() && j < 2) {
							tasks = taskQueue;
							taskQueues.set(j, new LinkedList<Task>());
						} else if (!taskQueue.isEmpty()) {
							tasks = new LinkedList<Task>();
							tasks.add(taskQueue.remove());
						}
						
						if (tasks != null) {
							DatapathId dpid = priorityTaskQueue.getDpid();
							Map<DatapathId, Integer> counters = workerSwitchesTasks.get(workerId);
							counters.put(dpid, counters.get(dpid) + 1);
							
							break;
						}
					}
					priorityTaskQueues.add(priorityTaskQueue);
					
					if (tasks != null)
						break;
				}
				
				if (tasks == null)
					try {
						conditions.get(lock).await();
					} catch (InterruptedException e) {
						logger.error(e.toString());
					}
				else {
					
					break;
				}
			}
			lock.unlock();
			
//			logger.info("Tester - Scheduler - Get Task: {}", workerId);
			return tasks;
		}
		
		public void schedule() {
			
		}
		
		public void addSwitch(DatapathId dpid) {
			
			int minTotalTasks = -1;
			int minTotalSwitches = -1;
			String minValueWorker = null;
			
			synchronized(workerTaskMapping) {
				for (String workerId : workers.keySet()) {
					Lock lock = workerLocks.get(workerId);
					
					
					int totalTasks = 0;
					int totalSwitches = 0;
					
					lock.lock();
					
					Map<DatapathId, Integer> counters = workerSwitchesTasks.get(workerId);
					for (int counter : counters.values()) {
						totalTasks += counter;
					}
					
					totalSwitches = workerTaskMapping.get(workerId).size();
					
					lock.unlock();
					
					if (minTotalTasks == -1 || minTotalTasks > totalTasks
							|| (minTotalTasks == totalTasks && minTotalSwitches > totalSwitches)) {
						minTotalTasks = totalTasks;
						minTotalSwitches = totalSwitches;
						minValueWorker = workerId;
					}
				}
				
				Lock lock = workerLocks.get(minValueWorker);
				
				synchronized(switchLocks) {
					switchLocks.put(dpid, lock);
				}
				
				lock.lock();
				
				PriorityTaskQueues priorityTaskQueues = new PriorityTaskQueues(dpid, 3);
				workerTaskMapping.get(minValueWorker).add(priorityTaskQueues);
				switchTaskMapping.put(dpid, priorityTaskQueues);
				
				Map<DatapathId, Integer> counters = workerSwitchesTasks.get(minValueWorker);
				counters.put(dpid, 0);
				
				for (String workerId : workerTaskMapping.keySet()) {
					Queue<PriorityTaskQueues> taskQueues = workerTaskMapping.get(workerId);
					Iterator<PriorityTaskQueues> iter = taskQueues.iterator();
					while ( iter.hasNext() ) {
						PriorityTaskQueues taskQueue = iter.next();
						logger.info("Tester - Scheduler - Parameters Worker Task Mapping: {} {}",
								workerId, taskQueue.getDpid().toString());
					}
				}
				
				lock.unlock();
			}
		}
		
//		public void employWorkers(int n) {
//			Worker w = new Worker(this);
//		}
		
		private class PriorityTaskQueues {
			private DatapathId dpid;
			private List<Queue<Task>> priorityTaskQueues;
			private int level;
			
			public PriorityTaskQueues(DatapathId dpid, int level) {
				this.dpid  = dpid;
				this.level = level;
				priorityTaskQueues = new ArrayList<Queue<Task>>();
				
				for (int i = 0; i < level; i ++) {
					priorityTaskQueues.add(new LinkedList<Task>());
				}
			}
			
			public DatapathId getDpid() {
				return dpid;
			}
			
			public int getLevel() {
				return level;
			}
			
			public List<Queue<Task>> getTaskQueues() {
				return priorityTaskQueues;
			}
			
			public Queue<Task> getTaskQueue(int i) {
				if (i < level)
					return priorityTaskQueues.get(i);
				return null;
			}
			
			public boolean isEmpty() {
				for (Queue<Task> taskQueue : priorityTaskQueues) {
					if (!taskQueue.isEmpty())
						return false;
				}
				
				return true;
			}
		}
	}
	
	private void activeCollectionThread() throws InterruptedException{
		while(true) {
//			HashMap<DatapathId, Boolean> criticalSwitches = new HashMap<DatapathId, Boolean>();
			
//			double possibility = power / (switches.size() * 10.0);
//			for (DatapathId dpid : latestAddress.keySet()) {
//				List<IPv4Address> addresses = latestAddress.get(dpid);
//				List<IPv4Address> removes = new ArrayList<IPv4Address>();
//				for (IPv4Address address : addresses) {
//					if (Math.random() > possibility)
//						continue;
//					Task task = new Task(dpid.toString(), TaskType.DEL_COLLECTION_RULE,
//							dpid, address, 16);
//					inferiorTaskQueue.put(task);
////					switchTaskQueue.get(dpid).put(task);
//					criticalSwitches.put(dpid, true);
//					
//					removes.add(address);
//				}
//				
//				for (IPv4Address remove : removes)
//					addresses.remove(remove);
//			}
//			
//			for (DatapathId dpid : switches) {
//				if (Math.random() <= 1.0/8.0) {
//					
//					List<IPv4Address> addresses;
//					if (latestAddress.containsKey(dpid))
//						addresses = latestAddress.get(dpid);
//					else {
//						addresses = new ArrayList<IPv4Address>();
//						latestAddress.put(dpid, addresses);
//					}
//					 
//					int number = (int)(5*Math.random()) + 1;
//					if (number + addresses.size() > 10)
//						number = 10 - addresses.size();
//					
//					for (int i = 0; i < number; i ++) {
//					    int high = (int)(Math.random()*256);
//					    IPv4Address address = IPv4Address.of(String.format("%d.%d.%d.%d", high, 0, 0, 0));
//					    if (addresses.contains(address)) {
//					    	high = (int)(Math.random()*256);
//						    address = IPv4Address.of(String.format("%d.%d.%d.%d", high, 0, 0, 0));
//					    }
//					    
//					    Task task = new Task(dpid.toString(), TaskType.ADD_COLLECTION_RULE,
//								dpid, address, 8);
//					    
//					    inferiorTaskQueue.put(task);
////						switchTaskQueue.get(dpid).put(task);
//						criticalSwitches.put(dpid, true);
//						
//					    addresses.add(address);
//						power += 1.0;
//					}
//				}
//			}
//			
//			for (DatapathId dpid : switches) {
//				
//				IOFSwitch sw = switchService.getSwitch(dpid);
//				Collection<OFPort> ports = sw.getEnabledPortNumbers();
//				if (criticalSwitches.containsKey(dpid))
//						continue;
//				
//				for (OFPort port : ports) {
//					String key = String.format("%s-%d", dpid.toString(), port.getPortNumber());
//					
//					Task task = new Task(key, TaskType.PORT_STATISTICS_COLLECTION, dpid, port);
//					priorTaskQueue.put(task);
////					switchTaskQueue.get(dpid).put(task);
//					
////					logger.info("Experiment - Task - Active-Collection Tasks: {}",
////							String.format("![%d] ![%d]", ++ timedTasks, System.currentTimeMillis()));	// Experiment
//					
//				}
//			}
			
			for (DatapathId dpid : latestAddress.keySet()) {
				List<IPv4Address> addresses = latestAddress.get(dpid);
				List<IPv4Address> removes = new ArrayList<IPv4Address>();
				for (IPv4Address address : addresses) {
					
//					Task task = new Task(dpid.toString(), TaskType.DEL_COLLECTION_RULE,
//							dpid, address, 16);
//					scheduler.addTask(task);
					
					mergeCollectRules(dpid, address, 16, 8);
					removes.add(address);
				}
				
				for (IPv4Address remove : removes)
					addresses.remove(remove);
			}
			
			for (DatapathId dpid : switches) {
				if (Math.random() <= 1.0/8.0) {
					
					List<IPv4Address> addresses;
					if (latestAddress.containsKey(dpid))
						addresses = latestAddress.get(dpid);
					else {
						addresses = new ArrayList<IPv4Address>();
						latestAddress.put(dpid, addresses);
					}
					 
					int number = (int)(5*Math.random()) + 1;
					if (number + addresses.size() > 10)
						number = 10 - addresses.size();
					
					for (int i = 0; i < number; i ++) {
					    int high = (int)(Math.random()*256);
					    IPv4Address address = IPv4Address.of(String.format("%d.%d.%d.%d", high, 0, 0, 0));
					    if (addresses.contains(address)) {
					    	high = (int)(Math.random()*256);
						    address = IPv4Address.of(String.format("%d.%d.%d.%d", high, 0, 0, 0));
					    }
					    
//					    Task task = new Task(dpid.toString(), TaskType.ADD_COLLECTION_RULE,
//								dpid, address, 8);
//					    
//					    scheduler.addTask(task);
//						switchTaskQueue.get(dpid).put(task);
//						criticalSwitches.put(dpid, true);
						
					    splitCollectRules(dpid, address, 8, 16);
					    addresses.add(address);
						power += 1.0;
					}
				}
			}
			
			for (DatapathId dpid : switches) {
				
				IOFSwitch sw = switchService.getSwitch(dpid);
				Collection<OFPort> ports = sw.getEnabledPortNumbers();
//				if (criticalSwitches.containsKey(dpid))
//						continue;
				
				for (OFPort port : ports) {
					String key = String.format("%s-%d", dpid.toString(), port.getPortNumber());
					
					Task task = new Task(key, TaskType.PORT_STATISTICS_COLLECTION, dpid, port);
					scheduler.addTask(task);
//					switchTaskQueue.get(dpid).put(task);
					
//					logger.info("Experiment - Task - Active-Collection Tasks: {}",
//							String.format("![%d] ![%d]", ++ timedTasks, System.currentTimeMillis()));	// Experiment
					
				}
			}
			
			Thread.sleep(5*minInterval);
		}
	}
	
//	private void addTaskQueu(Task task) {
//		switch (task.getType()) {
//		case PORT_STATISTICS_COLLECTION:
//			break;
//		case FLOW_STATISTICS_COLLECTION:
//			break;
//		case ADD_COLLECTION_RULE:
//		case DEL_COLLECTION_RULE:
//		case BLOCK_COLLECTION_RULE:
//			taskLock.lock();
//			inferiorTaskQueue.add(task);
//			empty.signal();
//			taskLock.unlock();
//			break;
//		case ADJUST_RATIO:
//		default:
//			break;
//		}
//	}
	
	// Initialize flow tables and group tables
	private void initDefaultRules(IOFSwitch sw) {

		// Clear all rules.
		OFFlowDelete flowdel = sw.getOFFactory().buildFlowDelete()
				.setTableId(TableId.of(flowMonitorTbl))
				.build();
		sw.write(flowdel);
			
		// Add goto-next-table rule
		OFInstruction goto_tbl = sw.getOFFactory().instructions()
				.gotoTable(TableId.of(forwardingTbl));
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(goto_tbl);
			
		OFFlowAdd flowGoto = sw.getOFFactory().buildFlowAdd()
				.setPriority(zeroPriority)
				.setTableId(TableId.of(flowMonitorTbl))
				.setInstructions(instructions)
				.build();
		sw.write(flowGoto);
			
		// Add packet-in rule for forwarding-table
		OFAction to_ctrl = sw.getOFFactory().actions().buildOutput()
				.setMaxLen(0xFFffFFff)
				.setPort(OFPort.CONTROLLER)
				.build();
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(to_ctrl);
			
		OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
				.setPriority(zeroPriority)
				.setTableId(TableId.of(forwardingTbl))
				.setMatch(
						sw.getOFFactory().buildMatch().build())
				.setActions(actions)
				.build();
		sw.write(flowAdd);
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		
//		int index = 0, min = taskQueues.get(0).size();
//		for (int i = 1; i < taskQueues.size(); i ++) {
//			if (taskQueues.get(i).size() < min)
//				index = i;
//		}
		
		switches.add(switchId);
		initDefaultRules(switchService.getSwitch(switchId));
		scheduler.addSwitch(switchId);
		
//		LinkedBlockingQueue<Task> taskQueue = new LinkedBlockingQueue<Task>();
//		switchTaskQueue.put(switchId, taskQueue);
//		Worker w = new Worker(taskQueue);
//		workers.add(w);
//		w.start();
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
		// Logger
		logger = LoggerFactory.getLogger(RadarManager.class);
		
		// Initialize services
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		
		// Initialize packet-in message handler threads 
//		taskQueue = new LinkedBlockingQueue<Task>();
//		taskQueues = new ArrayList<BlockingQueue<Task>>();
//		taskLocks = new ArrayList<Lock>();
//		conditions = new ArrayList<Condition>();
		
//		priorTaskQueue    = new LinkedBlockingQueue<Task>();
//		inferiorTaskQueue = new LinkedBlockingQueue<Task>();
		
		
		
//		switchTaskQueue = new HashMap<DatapathId, BlockingQueue<Task>>();
		
		switches  = new ArrayList<DatapathId>();
		scheduler = new Scheduler(10);
		
//		Worker w1 = new Worker(priorTaskQueue);
//		Worker w2 = new Worker(inferiorTaskQueue);
//		workers.add(w1);
//		workers.add(w2);
//		w1.start();
//		w2.start();
//		BlockingQueue<Task> taskQueue = new LinkedBlockingQueue<Task>();
//		
//		taskQueues.add(taskQueue);
//
//		for (int i = 0; i < numWorker; i ++) {
//			
//			Worker w = new Worker(taskQueue);
//			workers.add(w);
//			w.start();
//		}
		
//		portStatsLock = new ReentrantReadWriteLock();
//		flowsStatsLock = new ReentrantReadWriteLock();
//		readPortStatsLock     = portStatsLock.readLock();
//		writePortStatsLock    = portStatsLock.writeLock();
//		readFlowsStatsLock    = flowsStatsLock.readLock();
//		writeFlowsStatsLock   = flowsStatsLock.writeLock();
		
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
		
		flowsStats = new HashMap<DatapathId, HashMap<String, OFStatistic>>();
		
		latestAddress = new HashMap<DatapathId, List<IPv4Address>>();
		power = 0.0;
		
		// Experiment
//		activeTasks     = 0;
//		triggeredTasks  = 0;
//		timedTasks      = 0;
//		failedTasks     = 0;
//		
//		portStatsRequests  = 0;
//		flowsStatsRequests = 0;
//		addFlowRequests    = 0;
//		delFlowRequests    = 0;
//		blockFlowRequests  = 0;
		

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
		return RadarManager.class.getSimpleName();
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
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m
			= new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
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
