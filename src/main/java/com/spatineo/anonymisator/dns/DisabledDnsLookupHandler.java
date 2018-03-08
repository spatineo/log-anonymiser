package com.spatineo.anonymisator.dns;

public class DisabledDnsLookupHandler implements DnsLookupHandler {

	private DnsLookupResult result;
	
	public DisabledDnsLookupHandler() {
		DnsLookupResult tmp = new DnsLookupResult();
		tmp.setSuccess(false);
		result = tmp;
	}
	
	@Override
	public DnsLookupResult lookup(String addr) {
		return result;
	}

}
