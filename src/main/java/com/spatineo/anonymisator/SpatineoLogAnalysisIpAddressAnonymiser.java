package com.spatineo.anonymisator;

import com.spatineo.anonymisator.dns.DnsLookupService;

public class SpatineoLogAnalysisIpAddressAnonymiser implements IpAddressAnonymiser {

	private DnsLookupService dnsLookupService;
	
	public void setDnsLookupService(DnsLookupService dnsLookupService) {
		this.dnsLookupService = dnsLookupService;
	}
	
	public DnsLookupService getDnsLookupService() {
		return dnsLookupService;
	}
	
	@Override
	public String processAddressString(String address) {
		// TODO: this processing needs to be parallelized more

		
		
		return "{!1{" + "}}";
	}

}
