package com.spatineo.anonymisator.dns;

import java.util.concurrent.TimeUnit;

/**
 * Processes a single DNS lookup, must be thread safe and perform within the given timeout.
 *  
 * @author v2
 */
public interface DnsLookupHandler {
	public DnsLookupResult lookup(String addr) throws Exception;
}
