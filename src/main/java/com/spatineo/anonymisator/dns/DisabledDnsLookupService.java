package com.spatineo.anonymisator.dns;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

public class DisabledDnsLookupService implements DnsLookupService {

	private Future<DnsLookupResult> result;
	
	public DisabledDnsLookupService() {
		DnsLookupResult tmp = new DnsLookupResult();
		tmp.setSuccess(false);
		result = CompletableFuture.completedFuture(tmp);
	}
	
	@Override
	public Future<DnsLookupResult> lookup(String addr) {
		return result;
	}

}
