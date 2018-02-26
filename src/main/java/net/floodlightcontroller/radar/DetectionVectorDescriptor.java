package net.floodlightcontroller.radar;

public class DetectionVectorDescriptor extends VectorDescriptor {
	
	private int triggerRate;
	private int statType;
	
	private boolean sourceLocation;
	
	public static final int NONE_STATISTIC = 0;
	public static final int FLOW_STATISTIC = 1;
	public static final int PORT_STATISTIC = 2;

	public DetectionVectorDescriptor(int triggerRate, int statType, boolean sourceLocation) {
		this.triggerRate = triggerRate;
		this.statType = statType;
		this.sourceLocation = sourceLocation;
	}
	
	public int getTriggerRate() {
		return triggerRate;
	}
	
	public int getStatType() {
		return statType;
	}
	
	public boolean containsStatType(int statType) {
		return (this.statType & statType) == statType;
	}

	public boolean isSourceLocation() {
		return sourceLocation;
	}
}
