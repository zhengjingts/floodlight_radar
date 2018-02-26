package net.floodlightcontroller.radar;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SuspiciousTable {
	
	protected final String key;
	
	protected final int splitRate;
	protected final int maxSplitLevel;
	protected final int maxLocationRules;
	
	protected final double significance;
	
	// to determine if a node should be blocked
	protected final int score;
	
	// to determine if a node could be merged
	protected long decay;
	
	protected final boolean mergeable;
	
	protected Map<IPv4AddressWithMask, SuspiciousNode> suspiciousNodes;
	protected Map<IPv4AddressWithMask, SuspiciousNode> blockedNodes;
	
	private SuspiciousNode root;
	
	public final CumulationComparator cumulationComparator = new CumulationComparator();
	public final ComplementComparator complementComparator = new ComplementComparator();
	
	// Debug
	protected static Logger logger;
	
	public SuspiciousTable(String key, int splitRate, int maxSplitLevel, int maxLocationRules, 
			double significance, int score, long decay, boolean mergeable) {
		
		this.key = key;
		
		this.splitRate     = splitRate;
		this.maxSplitLevel = maxSplitLevel;
		this.maxLocationRules = maxLocationRules;
		
		this.significance = significance;
		this.score = score;
		this.decay = decay;
		
		this.mergeable = mergeable;
		
		suspiciousNodes = new HashMap<IPv4AddressWithMask, SuspiciousNode>();
		blockedNodes    = new HashMap<IPv4AddressWithMask, SuspiciousNode>();
		
		root = new SuspiciousNode(IPv4AddressWithMask.of("0.0.0.0/0"), null, 0);
		suspiciousNodes.put(IPv4AddressWithMask.of("0.0.0.0/0"), root);
		
		logger = LoggerFactory.getLogger(SuspiciousTable.class);
		
	}
	
	public SuspiciousNode getRoot() {
		return root;
	}
	
	public SuspiciousNode retrieve(IPv4AddressWithMask address) {
		return suspiciousNodes.get(address);
	}
	
	public List<IPv4AddressWithMask> getSuspiciousAddresses() {
		List<IPv4AddressWithMask> suspiciousAddresses = new ArrayList<IPv4AddressWithMask>();
		for (IPv4AddressWithMask address : suspiciousNodes.keySet()) {
			if (!address.equals(IPv4AddressWithMask.of("0.0.0.0/0")))
				suspiciousAddresses.add(address);
		}
		
		return suspiciousAddresses;
	}
	
	public void locate(Map<IPv4AddressWithMask, Double> updateValues, List<IPv4AddressWithMask> splitted,
			List<IPv4AddressWithMask> merged, List<IPv4AddressWithMask> blocked, long updateTime) {
		update(updateValues);
		
		List<SuspiciousNode> candidates = elect();
		
		List<SuspiciousNode> splitCandidates = new ArrayList<SuspiciousNode>();
		List<SuspiciousNode> blockCandidates = new ArrayList<SuspiciousNode>();
		promote(candidates, splitCandidates, blockCandidates, updateTime);
		
		for (SuspiciousNode blockedNode : blockCandidates) {
			blocked.add(blockedNode.getAddress());
			blockedNodes.put(blockedNode.getAddress(), blockedNode);
		}
		
		List<SuspiciousNode> splittedNodes = new ArrayList<SuspiciousNode>();
		List<SuspiciousNode> mergedNodes   = new ArrayList<SuspiciousNode>();
		split(splitCandidates, splittedNodes, mergedNodes, updateTime);
		
		for (SuspiciousNode splittedNode : splittedNodes)
			splitted.add(splittedNode.getAddress());
		for (SuspiciousNode mergedNode : mergedNodes)
			merged.add(mergedNode.getAddress());
		
		logger.info("Experiment - Control - Splitted And Merged Nodes: {}", String.format("![%s] ![%d] ![%d] ![%d] ![%d]",
				key, suspiciousNodes.size(), splitted.size(), merged.size(), System.currentTimeMillis()));
	}
	
	private void update(Map<IPv4AddressWithMask, Double> updateValues) {
		clearAdditions();
		
		for (IPv4AddressWithMask address : updateValues.keySet()) {
			if (!suspiciousNodes.containsKey(address))
				continue;
			
			SuspiciousNode node = suspiciousNodes.get(address);
			double delta = updateValues.get(address);
			
			node.addCumulation(delta);
			node.addVersion();
			node.addAddition(delta);
			
			// if children are not full
			if (getDemand(node) > 0) {
				node.addComplement(delta);
				node.addComplementVersion();
			}
			
			// Upward update
			while (node.getParent() != null) {
				node = node.getParent();
				node.addCumulation(delta);
				node.addAddition(delta);
			}
		}
		
		// For Debug
		for (SuspiciousNode node : suspiciousNodes.values()) {
			logger.debug("Node Info: {}", String.format("%s %f/%d ~ %f, %f/%d ~ %f, %f", node.getAddress().toString(),
					node.getCumulation(), node.getVersion(), node.getSuspicious(), node.getComplement(),
					node.getComplementVersion(), node.getComplementSuspicious(), node.getAddition()));
		}
	}
	
	private List<SuspiciousNode> elect() {
		double sum = 0.0;
		int    level = 0;
		List<SuspiciousNode> peerNodes = new ArrayList<SuspiciousNode>();
		List<SuspiciousNode> parentNodes = new ArrayList<SuspiciousNode>();
		
		if (root.getAddition() > 0) {
			peerNodes.add(root);
			sum = root.getSuspicious();
		}
		
		List<SuspiciousNode> candidates = new ArrayList<SuspiciousNode>();
		while (true) {
			double aggregation = 0.0;
			double localSum = 0.0;
			List<SuspiciousNode> newPeerNodes   = new ArrayList<SuspiciousNode>();
			List<SuspiciousNode> newParentNodes = new ArrayList<SuspiciousNode>();
			
			Collections.sort(peerNodes, cumulationComparator);
			Collections.sort(parentNodes, complementComparator);
			
			sum *= significance;
			
			// For Debug
			logger.info("Debug - Suspicious Value - Iteration: {}", String.format("![%s] ![%d] ![%f]", key, level, sum));
			for (SuspiciousNode node : peerNodes)
				logger.info("Debug - Suspicious Value - Sorted Peer Nodes: {}", String.format("![%s] ![%s] ![%f] ![%f]",
						key, node.getAddress().toString(), node.getSuspicious(), node.getComplementSuspicious()));
			for (SuspiciousNode node : parentNodes)
				logger.info("Debug - Suspicious Value - Sorted Parent Nodes: {}", String.format("![%s] ![%s] ![%f] ![%f]",
						key, node.getAddress().toString(), node.getSuspicious(), node.getComplementSuspicious()));
			
			int i = peerNodes.size() - 1, j = parentNodes.size() - 1;
			while (i >= 0 || j >= 0) {
				if (aggregation >= sum)
					break;
				
				SuspiciousNode node = null;
				if (i < 0) {
					node = parentNodes.get(j);
					aggregation += node.getComplementSuspicious();
					j --;
				} else if (j < 0) {
					node = peerNodes.get(i);
					aggregation += node.getSuspicious();
					i --;
				} else if (peerNodes.get(i).getSuspicious() >= parentNodes.get(j).getComplementSuspicious()) {
					node = peerNodes.get(i);
					aggregation += node.getSuspicious();
					i --;
				} else {
					node = parentNodes.get(j);
					aggregation += node.getComplementSuspicious();
					j --;
				}
				
				if (node.getChildren().size() == 0) {
					candidates.add(node);
					logger.info("Debug - Suspicious Value - Split Candidate: {}", String.format("![%s] ![%s] ![%f]",
							key, node.getAddress().toString(), node.getSuspicious()));
					continue;
				}
				
				if (node.getPrefix() < level) {
					candidates.add(node);
					logger.info("Debug - Suspicious Value - Split Candidate: {}", String.format("![%s] ![%s] ![%f]",
							key, node.getAddress().toString(), node.getComplementSuspicious()));
					continue;
				}
				
				// If add all complement suspicious could rise the accuracy of location?
				// Recent experiments show the answer is no.
//				localSum += node.getComplementSuspicious();
//				for (SuspiciousNode child : node.getChildren())
//					localSum += child.getSuspicious();
				
				if (node.getAddition() > 0) {
					if (node.getComplementSuspicious() > 0) {
						localSum += node.getComplementSuspicious();
						newParentNodes.add(node);
					}
					
					for (SuspiciousNode child : node.getChildren())
						if (child.getSuspicious() > 0 && child.getAddition() > 0) {
							localSum += child.getSuspicious();
							newPeerNodes.add(child);
						}
				}
			}
			
			if (newPeerNodes.size() == 0 && newParentNodes.size() == 0)
				break;
			
			if (level == maxSplitLevel)
				break;
			
			sum         = localSum;
			peerNodes   = newPeerNodes;
			parentNodes = newParentNodes;
			
			level += splitRate;
			if (level > maxSplitLevel)
				level = maxSplitLevel;
		}
		
		return candidates;
	}
	
	private void promote(List<SuspiciousNode> candidates, List<SuspiciousNode> splitCandidates,
			List<SuspiciousNode> blockCandidates, long currentTime) {
		
		for (SuspiciousNode candidate : candidates) {
			if (candidate.getPrefix() == maxSplitLevel) {
				if (blockedNodes.containsKey(candidate.getAddress()))
					continue;
				
				if (candidate.incrScore() >= score)
					blockCandidates.add(candidate);
				else
					logger.info("Experiment - Detection - Add Score: {}", String.format("![%s] ![%s] ![%d] ![%d]",
							key, candidate.getAddress().toString(), candidate.getScore(), currentTime));
			} else {
				splitCandidates.add(candidate);
				candidate.incrScore();
			}
				
			// Recursively update time of nodes
			SuspiciousNode currentNode = candidate;
			while (currentNode != null) {
				if (currentNode.getPromotionTime() == currentTime)
					break;
				currentNode.setPromotionTime(currentTime);
				currentNode = currentNode.getParent();
			}
		}
	}
	
	private void split(List<SuspiciousNode> splitCandidates, List<SuspiciousNode> splittedNodes,
			List<SuspiciousNode> mergedNodes, long currentTime) {
		
		Collections.sort(splitCandidates, complementComparator);
		
		// If there are enough space for splitting, then split.
		while (splitCandidates.size() != 0) {
			SuspiciousNode candidate = splitCandidates.remove(splitCandidates.size()-1);
			
			int demand = getDemand(candidate);
			if (demand == 0)
				continue;
			
			if (suspiciousNodes.size() + demand <= maxLocationRules) {
				splittedNodes.addAll(splitNode(candidate, currentTime));
				logger.info("Experiment - Detection - Split: {}",
						String.format("![%s] ![%s]", key, candidate.getAddress().toString()));
			} else {
				splitCandidates.add(candidate);
				break;
			}
		}
		
		if (!mergeable)
			return;
		
		if (splitCandidates.size() == 0)
			return;
		
		// If there are no enough space for splitting, then try to merge.
		double maxSuspicious = splitCandidates.get(splitCandidates.size()-1).getComplementSuspicious();
		
		List<SuspiciousNode> mergeCandidates = new ArrayList<SuspiciousNode>();
		
		Queue<SuspiciousNode> queue = new LinkedList<SuspiciousNode>();
		queue.addAll(root.getChildren());
		while (queue.size() != 0) {
			SuspiciousNode parent = queue.remove();
			List<SuspiciousNode> children = parent.getChildren();
			
//			logger.info("Debug - Merge - Choose: {}", String.format("%s %f %d",
//					parent.getAddress().toString(), parent.getSuspicious(), parent.getPromotionTime()));
			
			if (children.size() != 0)
				queue.addAll(children);
			else if ((parent.getSuspicious() < maxSuspicious) && (currentTime - parent.getPromotionTime() >= decay)
					&& !blockedNodes.containsKey(parent.getAddress()) && (parent.getPrefix() > 0))
				mergeCandidates.add(parent);
		}
		
		Collections.sort(mergeCandidates, cumulationComparator);
		
		while (splitCandidates.size() != 0 && mergeCandidates.size() != 0) {
			SuspiciousNode splitCandidate = splitCandidates.remove(splitCandidates.size()-1);
			List<SuspiciousNode> premergeCandidates = new ArrayList<SuspiciousNode>();
			
			int demand = getDemand(splitCandidate) - maxLocationRules + suspiciousNodes.size();
			
			while (premergeCandidates.size() < demand && mergeCandidates.size() > 0) {
				SuspiciousNode mergeCandidate = mergeCandidates.remove(0);
				if (splitCandidate.getComplementSuspicious() <= mergeCandidate.getSuspicious())
					break;
				else
					premergeCandidates.add(mergeCandidate);
			}
			
			if (premergeCandidates.size() == demand) {
				mergedNodes.addAll(premergeCandidates);
				for (SuspiciousNode mergeCandidate : premergeCandidates) {
					if (mergeCandidate.getParent() != null)
						mergeCandidate.getParent().removeChild(mergeCandidate);
					suspiciousNodes.remove(mergeCandidate.getAddress());
					
					logger.info("Experiment - Control - Merge: {}",
							String.format("![%s] ![%s]", key, mergeCandidate.getAddress().toString()));
				}
				
				splittedNodes.addAll(splitNode(splitCandidate, currentTime));
				logger.info("Experiment - Control - Split: {}",
						String.format("![%s] ![%s]", key, splitCandidate.getAddress().toString()));
			} else 
				break;
		}
	}
	
	private List<SuspiciousNode> splitNode(SuspiciousNode parent, long updateTime) {
		List<SuspiciousNode> splitted = new ArrayList<SuspiciousNode>();
		
		IPv4Address ip = parent.getAddress().getValue();
		int prefix     = parent.getPrefix();
		
		if (prefix >= maxSplitLevel)
			return splitted;
		
		int newPrefix, d, lim, iter;
		newPrefix = (prefix + splitRate) < maxSplitLevel ? (prefix + splitRate) : maxSplitLevel;
		
		d    = 1 << (32 - newPrefix);
		lim  = 1 << (newPrefix - prefix);
		iter = ip.getInt();
		
		if (parent.getChildren().size() == lim)
			return splitted;
		
		for (int i = 0; i < lim; i ++, iter += d) {
			IPv4AddressWithMask newAddr = IPv4AddressWithMask.of(IPv4Address.of(iter),
					IPv4Address.ofCidrMaskLength(newPrefix));
			if (!suspiciousNodes.containsKey(newAddr)) {
				SuspiciousNode child = new SuspiciousNode(newAddr, parent, updateTime);
				suspiciousNodes.put(newAddr, child);
				splitted.add(child);
			}
		}
		
		parent.clearComplement();
		
		return splitted;
	}
	
	private int getDemand(SuspiciousNode node) {
		int level  = (maxSplitLevel - node.getPrefix()) < splitRate ? (maxSplitLevel - node.getPrefix()) : splitRate;
		return (1 << level) - node.getChildren().size();
	}
	
	private void clearAdditions() {
		for (SuspiciousNode node : suspiciousNodes.values())
			node.clearAddition();
	}
	
	public class CumulationComparator implements Comparator<SuspiciousNode> {

		@Override
		public int compare(SuspiciousNode x, SuspiciousNode y) {
			return Double.compare(x.getSuspicious(), y.getSuspicious());
		}
	}
	
	public class ComplementComparator implements Comparator<SuspiciousNode> {

		@Override
		public int compare(SuspiciousNode x, SuspiciousNode y) {
			return Double.compare(x.getComplementSuspicious(), y.getComplementSuspicious());
		}
	}
	
	protected class SuspiciousNode{
		
		private IPv4AddressWithMask address;
		private int prefix;
		
		private SuspiciousNode       parent;
		private List<SuspiciousNode> children;
		
		private double cumulation;
		private double complement;
		private double addition;
		
		private int    score;
		
		// To protect new node not to be merged in \tao time
		private long promotionTime;
		
		// To record update times for calculating suspicious
		private int version;
		private int complementVersion;
		
		public SuspiciousNode(IPv4AddressWithMask address, SuspiciousNode parent, long promotionTime) {
			this.address = address;
			this.prefix  = address.getMask().asCidrMaskLength();
			
			this.parent   = parent;
			this.children = new ArrayList<SuspiciousNode>();
			if (parent != null)
				parent.addChild(this);
			
			this.cumulation = 0.0;
			this.complement = 0.0;
			
			this.score      = 0;
			
			this.promotionTime = promotionTime;
			
			this.version           = 0;
			this.complementVersion = 0;
		}
		
		public IPv4AddressWithMask getAddress() {
			return address;
		}
		
		public int getPrefix() {
			return prefix;
		}
		
		public double getCumulation() {
			return cumulation;
		}
		
		public void addCumulation(double delta) {
			cumulation += delta;
		}
		
		public double getComplement() {
			return complement;
		}
		
		public void addComplement(double delta) {
			complement += delta;
		}
		
		public void clearComplement() {
			complement        = 0.0;
			complementVersion = 0;
		}
		
		public double getAddition() {
			return addition;
		}
		
		public void addAddition(double delta) {
			addition += delta;
		}
		
		public void clearAddition() {
			addition = 0.0;
		}
		
		public int getScore() {
			return score;
		}
		
		public int incrScore() {
			return ++ score;
		}
		
		public SuspiciousNode getParent() {
			return parent;
		}
		
		public List<SuspiciousNode> getChildren() {
			return children;
		}

		public void addChild(SuspiciousNode child) {
			children.add(child);
		}
		
		public void removeChild(SuspiciousNode child) {
			children.remove(child);
		}
		
		public long getPromotionTime() {
			return promotionTime;
		}

		public void setPromotionTime(long promotionTime) {
			this.promotionTime = promotionTime;
		}
		
		public double getSuspicious() {
//			if (version == 0)
//				return 0.0;
//			return cumulation/version;
			return cumulation;
		}
		
		public double getComplementSuspicious() {
//			if (complementVersion == 0)
//				return 0.0;
//			return complement/complementVersion;
			return complement;
		}
		
		public double getAdditionSuspicious() {
			return addition;
		}
		
		public void addVersion() {
			version ++;
		}
		
		public void addComplementVersion() {
			complementVersion ++;
		}
		
		public int getVersion() {
			return version;
		}
		
		public int getComplementVersion() {
			return complementVersion;
		}
	}
}
