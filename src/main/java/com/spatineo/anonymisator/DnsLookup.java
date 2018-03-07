package com.spatineo.anonymisator;

public class DnsLookup {
	
	private boolean enabled;
	private String server;
	
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public boolean isEnabled() {
		return enabled;
	}
	
	public void setServer(String server) {
		this.server = server;
	}
	
	public String getServer() {
		return server;
	}
}
