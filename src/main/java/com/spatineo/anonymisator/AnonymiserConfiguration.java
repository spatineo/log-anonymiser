package com.spatineo.anonymisator;

/*-
 * #%L
 * log-anonymisator
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 Spatineo Inc
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

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
