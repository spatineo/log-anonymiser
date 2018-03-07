package com.spatineo.anonymisator.dns;

import java.util.concurrent.Future;

public interface DnsLookupService {
	public Future<DnsLookupResult> lookup(String addr);
}
