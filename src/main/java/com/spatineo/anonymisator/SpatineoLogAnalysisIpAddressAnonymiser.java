package com.spatineo.anonymisator;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsLookupResult;

public class SpatineoLogAnalysisIpAddressAnonymiser implements IpAddressAnonymiser {
	private static Logger logger = LoggerFactory.getLogger(SpatineoLogAnalysisIpAddressAnonymiser.class);
	
	private DnsLookupHandler dnsLookupHandler;
	private int ipv4BitsToAnonymize;
	private int ipv6BitsToAnonymize;
	
	private String ipv4MaskPostfix;
	private String ipv6MaskPostfix;
	
	public void setDnsLookupHandler(DnsLookupHandler dnsLookupHandler) {
		this.dnsLookupHandler = dnsLookupHandler;
	}
	
	public DnsLookupHandler getDnsLookupHandler() {
		return dnsLookupHandler;
	}
	
	public void setIpv4BitsToAnonymize(int ipv4BitsToAnonymize) {
		this.ipv4BitsToAnonymize = ipv4BitsToAnonymize;
		this.ipv4MaskPostfix = "/"+(32-this.ipv4BitsToAnonymize);
	}
	
	public int getIpv4BitsToAnonymize() {
		return ipv4BitsToAnonymize;
	}
	
	public void setIpv6BitsToAnonymize(int ipv6BitsToAnonymize) {
		this.ipv6BitsToAnonymize = ipv6BitsToAnonymize;
		this.ipv6MaskPostfix = "/"+(128-this.ipv6BitsToAnonymize);
	}
	
	public int getIpv6BitsToAnonymize() {
		return ipv6BitsToAnonymize;
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
		if (ipAddress.contains(":")) {
			if (ipv6MaskPostfix == null) {
				throw new IllegalStateException("Number of IPv6 anonymising bits has not been specified");
			}
			return anonymiseAnyAddress(ipAddress, getIpv6BitsToAnonymize(), ipv6MaskPostfix);
		} else {
			if (ipv4MaskPostfix == null) {
				throw new IllegalStateException("Number of IPv4 anonymising bits has not been specified");
			}
			return anonymiseAnyAddress(ipAddress, getIpv4BitsToAnonymize(), ipv4MaskPostfix);
		}
	}


	private String anonymiseAnyAddress(String ipAddress, int bitsToAnonymise, String postfix) {
		InetAddress addr = InetAddresses.forString(ipAddress);
		byte [] bbb = addr.getAddress();
		
		try {
			int idx = bbb.length-1;
			int bitsToZero = bitsToAnonymise;
			
			while (bitsToZero >= 8) {
				bbb[idx] = 0;
				idx--;
				bitsToZero -= 8;
			}
			
			if (bitsToZero > 0) {
				bbb[idx] = (byte) (bbb[idx] & (0xff ^ (1 << bitsToZero)-1));
			}
			
			InetAddress masked = InetAddress.getByAddress(bbb);
			
			return InetAddresses.toAddrString(masked) + postfix;
		} catch(UnknownHostException uhe) {
			throw new IllegalArgumentException("Unknown host exception when turning bits into ipv6 address?!", uhe);
		}
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
