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

import static org.junit.Assert.*;

import org.apache.commons.net.util.SubnetUtils;
import org.junit.Before;
import org.junit.Test;

public class IpAddressAnonymiserTest {
	SpatineoLogAnalysisIpAddressAnonymiser ipAddressAnonymiser;
	
	@Before
	public void setUp() throws Exception {
		ipAddressAnonymiser = new SpatineoLogAnalysisIpAddressAnonymiser();
	}

	@Test
	public void testDomainNameExtraction() {
		String name = ipAddressAnonymiser.identifyDomainName("www.google.com");
		assertEquals("google.com", name);
	}
	
	@Test
	public void testDomainNameExtractionCoUk() {
		String name = ipAddressAnonymiser.identifyDomainName("www.ordnancesurvey.co.uk");
		assertEquals("ordnancesurvey.co.uk", name);
	}

	@Test
	public void testDomainNameExtractionCyprus() {
		String name = ipAddressAnonymiser.identifyDomainName("weba.moi.dls.gov.cy");
		assertEquals("dls.gov.cy", name);
	}


	@Test
	public void testBareTldNoDomain() {
		try {
			ipAddressAnonymiser.identifyDomainName("com");
			fail("'com' should not be a valid domain name");
		} catch(Exception e) {
			assertTrue(e instanceof IllegalStateException);
		}
	}
	
	@Test
	public void testIpv4Masking8Bits() {
		ipAddressAnonymiser.setIpv4BitsToAnonymize(8);
		String result = ipAddressAnonymiser.anonymiseIp("192.168.1.127");
		
		assertEquals("192.168.1.0/24", result);
	}
	

	@Test
	public void testIpv4Masking6Bits() {
		ipAddressAnonymiser.setIpv4BitsToAnonymize(6);
		String result = ipAddressAnonymiser.anonymiseIp("192.168.1.218");
		
		assertEquals("192.168.1.192/26", result);
	}
	
	@Test
	public void testIpv4Masking7Bits() {
		String addr = "192.168.1.255";
		ipAddressAnonymiser.setIpv4BitsToAnonymize(7);
		String result = ipAddressAnonymiser.anonymiseIp(addr);
		
		assertEquals("192.168.1.128/25", result);
		
		SubnetUtils tmp = new SubnetUtils(addr+"/25");
		String foo = tmp.getInfo().getNetworkAddress()+"/25";
		
		assertEquals(result, foo);
	}
	
	@Test
	public void testAllAnonBitsAndMatchWithCommonsNet() {
		String addr = "255.255.255.255";
		
		for (int i = 0; i <= 32; i++) {
			String postfix = "/"+(32-i);
			ipAddressAnonymiser.setIpv4BitsToAnonymize(i);
			String result = ipAddressAnonymiser.anonymiseIp(addr);
			
			SubnetUtils tmp = new SubnetUtils(addr+postfix);
			String foo = tmp.getInfo().getNetworkAddress()+postfix;
			
			assertEquals(result, foo);
		}
	}
	
	@Test
	public void testIpv6Masking80Bits() {
		ipAddressAnonymiser.setIpv6BitsToAnonymize(80);
		
		String result = ipAddressAnonymiser.anonymiseIp("fe80::f043:57ff:fe35:77c7");
		
		assertEquals("fe80::/48", result);
	}
	
	@Test
	public void testIpv6Masking80BitsWwwGoogleCom() { 
		ipAddressAnonymiser.setIpv6BitsToAnonymize(80);
		
		String result = ipAddressAnonymiser.anonymiseIp("2a00:1450:400f:80c::2004");
		
		assertEquals("2a00:1450:400f::/48", result);
	}
}
