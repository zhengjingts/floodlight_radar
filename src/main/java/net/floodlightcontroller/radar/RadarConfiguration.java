package net.floodlightcontroller.radar;

public class RadarConfiguration {
	
	private int maxLocationRules;
	
	private int splitRate;
	private int minSplitLevel;
	private int maxSplitLevel;
	
	private boolean mergeable;
	
	private int  score;
	private long decay;
	
	public RadarConfiguration() {
		
		this.maxLocationRules = 100000;
		
		this.minSplitLevel = 8;
		this.maxSplitLevel = 24;
		
		this.mergeable  = true;
		
		this.score = 3;
		this.decay = 3;
	}

	public int getMaxLocationRules() {
		return maxLocationRules;
	}

	public void setMaxLocationRules(int maxLocationrules) {
		this.maxLocationRules = maxLocationrules;
	}

	public int getSplitRate() {
		return splitRate;
	}

	public void setSplitRate(int splitRate) {
		this.splitRate = splitRate;
	}
	
	public int getMinSplitLevel() {
		return minSplitLevel;
	}

	public void setMinSplitLevel(int minSplitLevel) {
		this.minSplitLevel = minSplitLevel;
	}

	public int getMaxSplitLevel() {
		return maxSplitLevel;
	}

	public void setMaxSplitLevel(int maxSplitLevel) {
		this.maxSplitLevel = maxSplitLevel;
	}

	public boolean isMergeable() {
		return mergeable;
	}

	public void setMergeable(boolean mergeable) {
		this.mergeable = mergeable;
	}

	public int getScore() {
		return score;
	}

	public void setScore(int score) {
		this.score = score;
	}

	public long getDecay() {
		return decay;
	}

	public void setDecay(long decay) {
		this.decay = decay;
	}

}
