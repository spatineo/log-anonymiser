package com.spatineo.anonymisator;

import static org.junit.Assert.*;

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
}
