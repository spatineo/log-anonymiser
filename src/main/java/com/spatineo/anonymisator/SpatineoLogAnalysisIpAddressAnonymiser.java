package com.spatineo.anonymisator;

/*-
 * #%L
 * log-anonymisator
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 Spatineo Inc
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

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
	
	private boolean allowFullPrivateAddresses;
	
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
	
	public void setAllowFullPrivateAddresses(boolean allowFullPrivateAddresses) {
		this.allowFullPrivateAddresses = allowFullPrivateAddresses;
	}
	
	public boolean isAllowFullPrivateAddresses() {
		return allowFullPrivateAddresses;
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
			logger.error("Unknown error while processing address "+address+", treating as missing DNS name. Please report full error message with stack trace along with version of software to https://github.com/spatineo/log-anonymiser/issues", e);
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
	 * Convert FQDNs to top private domains, i.e. www.google.co.uk => google.co.uk
	 * For addresses not in public suffixes (like .com, .net, etc), this will either return null
	 * or the full address depending on isAllowFullPrivateAddresses(). 
	 * 
	 * @param dnsName Fully Qualified Domain Name (FQDN)
	 * @return Returns the domain name suitable for including in the resulting anonymised log file, or null
	 *         if this address cannot be used at all
	 */
	String identifyDomainName(String dnsName) {
		InternetDomainName idn;
		try {
			idn = InternetDomainName.from(dnsName);
		} catch(IllegalArgumentException iae) {
			if (logger.isTraceEnabled()) {
				logger.trace("Illegal DNS name "+dnsName, iae);
			}
			
			return null;
		}
		if (!idn.hasPublicSuffix()) {
			if (isAllowFullPrivateAddresses()) {
				return dnsName;
			} else {
				// topPrivateDomain() would fail for non-public suffix addresses
				return null;
			}
		}
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
