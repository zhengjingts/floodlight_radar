package net.floodlightcontroller.radar;

import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.types.U64;

public class VectorDescriptor {
	
	protected U64                 vectorId;
	protected Map<String, String> match;
	
	public VectorDescriptor() {
		match = new HashMap<String, String>();
	}

	public U64 getVectorId() {
		return vectorId;
	}

	public void setVectorId(U64 vectorId) {
		this.vectorId = vectorId;
	}
	
	public Map<String, String> getMatch() {
		return match;
	}
	
	public boolean hasMatchField(String field) {
		return match.containsKey(field);
	}
	
	public String getMatchField(String field) {
		return match.get(field);
	}
	
	public void setMatchField(String field, String value) {
		match.put(field, value);
	}
	
	public void delMatchField(String field) {
		match.remove(field);
	}
	
	public String toString() {
		String res = new String();
		for (String field : match.keySet())
			res = res.concat(field+"="+match.get(field)+",");
		
		if (res.length() > 0)
			return res.substring(0, res.length()-1);
		return res;
	}
}
