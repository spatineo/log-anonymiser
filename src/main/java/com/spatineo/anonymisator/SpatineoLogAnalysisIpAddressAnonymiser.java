package com.spatineo.anonymisator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsLookupResult;

public class SpatineoLogAnalysisIpAddressAnonymiser implements IpAddressAnonymiser {
	private static Logger logger = LoggerFactory.getLogger(SpatineoLogAnalysisIpAddressAnonymiser.class);
	
	private DnsLookupHandler dnsLookupHandler;
	
	public void setDnsLookupHandler(DnsLookupHandler dnsLookupHandler) {
		this.dnsLookupHandler = dnsLookupHandler;
	}
	
	public DnsLookupHandler getDnsLookupHandler() {
		return dnsLookupHandler;
	}
	
	@Override
	public String processAddressString(String address) {
		String domainName = null;
		String anonymisedIp = null;
		
		try {
			anonymisedIp = anonymiseIp(address);
			
			String reverseName = reverseName(address);
			
			domainName = identifyDomainName(reverseName);
			
		} catch(Exception e) {
			logger.error("Error in reverse DNS lookup", e);
		}
		
		return produceOutput(domainName, anonymisedIp);
	}
	
	
	String reverseName(String ipAddr) throws Exception {
		DnsLookupResult result = getDnsLookupHandler().lookup(ipAddr);
		
		if (result.isSuccess()) {
			return result.getReverseName();
		}
		
		return null;
	}
	
	String identifyDomainName(String dnsName) {
		return "foo.com";
	}
	
	String anonymiseIp(String address) {
		return "10.10.10.0/24";
	}
	
	
	String produceOutput(String domainName, String anonymisedIp) {
		StringBuffer ret = new StringBuffer("{!1{");
		ret.append(anonymisedIp);
		if (domainName != null) {
			ret.append(",");
			ret.append(domainName);
		}
		
		ret.append("}}");
		
		return ret.toString();
	}

}
