package com.spatineo.anonymisator;

import org.apache.commons.net.util.SubnetUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.InternetDomainName;
import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsLookupResult;

public class SpatineoLogAnalysisIpAddressAnonymiser implements IpAddressAnonymiser {
	private static Logger logger = LoggerFactory.getLogger(SpatineoLogAnalysisIpAddressAnonymiser.class);
	
	private DnsLookupHandler dnsLookupHandler;
	private int ipv4BitsToAnonymize;
	
	private String ipv4MaskPostfix;
	
	public void setDnsLookupHandler(DnsLookupHandler dnsLookupHandler) {
		this.dnsLookupHandler = dnsLookupHandler;
	}
	
	public DnsLookupHandler getDnsLookupHandler() {
		return dnsLookupHandler;
	}
	
	public void setIpv4BitsToAnonymize(int ipv4BitsToAnonymize) {
		this.ipv4BitsToAnonymize = ipv4BitsToAnonymize;
		this.ipv4MaskPostfix = "/"+(32-getIpv4BitsToAnonymize());
	}
	
	public int getIpv4BitsToAnonymize() {
		return ipv4BitsToAnonymize;
	}
	
	@Override
	public String processAddressString(String address) {
		String domainName = null;
		String anonymisedIp = null;
		
		try {
			anonymisedIp = anonymiseIp(address);
			
			String reverseName = reverseName(address);
			
			if (reverseName != null) {
				domainName = identifyDomainName(reverseName);
			}
			
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
	
	/**
	 * Convert FQDNs to top private domaines, i.e. www.google.co.uk => google.co.uk
	 * 
	 * @param dnsName
	 * @return
	 */
	String identifyDomainName(String dnsName) {
		InternetDomainName idn = InternetDomainName.from(dnsName);
		return idn.topPrivateDomain().toString();
	}
	
	String anonymiseIp(String ipAddress) {
		if (ipv4MaskPostfix == null) {
			throw new IllegalStateException("Number of IPv4 anonymising bits has not been specified");
		}
		SubnetUtils tmp = new SubnetUtils(ipAddress+ipv4MaskPostfix);
		return tmp.getInfo().getNetworkAddress()+ipv4MaskPostfix;
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
