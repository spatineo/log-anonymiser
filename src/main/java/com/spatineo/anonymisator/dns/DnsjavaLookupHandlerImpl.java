package com.spatineo.anonymisator.dns;

import java.util.concurrent.TimeUnit;

public class DnsjavaLookupHandlerImpl implements DnsLookupHandler {
	private DnsLookupConfiguration dnsLookupConfiguration;
	
	public void setDnsLookupConfiguration(DnsLookupConfiguration dnsLookupConfiguration) {
		this.dnsLookupConfiguration = dnsLookupConfiguration;
	}
	
	public DnsLookupConfiguration getDnsLookupConfiguration() {
		return dnsLookupConfiguration;
	}
	
	@Override
	public DnsLookupResult lookup(String addr, long timeout, TimeUnit unit) throws Exception {
		// TODO Auto-generated method stub
		
		DnsLookupResult ret = new DnsLookupResult();
		ret.setReverseName("hello.world.com");
		Thread.sleep((long)(timeout*0.05));
		return ret;
		
	}

}
