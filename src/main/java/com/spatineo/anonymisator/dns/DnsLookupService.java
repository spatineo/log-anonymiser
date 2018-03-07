package com.spatineo.anonymisator.dns;

import java.util.concurrent.Future;

/**
 * Services implementing this interface will performs parallel DNS lookups
 * 
 * @author v2
 *
 */
public interface DnsLookupService {
	public Future<DnsLookupResult> lookup(String addr);
}
