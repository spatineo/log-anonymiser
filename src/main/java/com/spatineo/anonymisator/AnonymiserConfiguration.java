package com.spatineo.anonymisator;

import java.util.List;

public class AnonymiserConfiguration {
	private boolean enabled;
	private List<String> servers;
	private int parallelThreads;
	private long timeoutMillis;
	private int ipv4BitsToAnonymize;
	private int ipv6BitsToAnonymize;
	
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
	
	public void setIpv4BitsToAnonymize(int ipv4BitsToAnonymize) {
		this.ipv4BitsToAnonymize = ipv4BitsToAnonymize;
	}
	
	public int getIpv4BitsToAnonymize() {
		return ipv4BitsToAnonymize;
	}
	
	public void setIpv6BitsToAnonymize(int ipv6BitsToAnonymize) {
		this.ipv6BitsToAnonymize = ipv6BitsToAnonymize;
	}
	
	public int getIpv6BitsToAnonymize() {
		return ipv6BitsToAnonymize;
	}
}
