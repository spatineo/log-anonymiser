package com.spatineo.anonymisator.dns;

public class DnsLookupResult {
	private boolean success;
	private String reverseName;
	
	public void setReverseName(String reverseName) {
		this.reverseName = reverseName;
	}
	
	public String getReverseName() {
		return reverseName;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}
	
	public boolean isSuccess() {
		return success;
	}
}
