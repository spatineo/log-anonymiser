package com.spatineo.anonymisator.dns;

import java.util.List;

public class DnsLookupConfiguration {
	private boolean enabled;
	private List<String> servers;
	private int parallelThreads;
	private long timeoutMillis;
	
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public boolean isEnabled() {
		return enabled;
	}
	
	public void setServers(List<String> servers) {
		this.servers = servers;
	}
	
	public List<String> getServers() {
		return servers;
	}
	
	public void setParallelThreads(int parallelThreads) {
		this.parallelThreads = parallelThreads;
	}
	
	public int getParallelThreads() {
		return parallelThreads;
	}
	
	public void setTimeoutMillis(long timeoutMillis) {
		this.timeoutMillis = timeoutMillis;
	}
	
	public long getTimeoutMillis() {
		return timeoutMillis;
	}
	
}
