package com.spatineo.anonymisator;

/*-
 * #%L
 * com.spatineo:log-anonymiser
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
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsLookupResult;

public class SpatineoLogAnalysisIpAddressAnonymiserTest {

	private SpatineoLogAnalysisIpAddressAnonymiser anonymiser;
	
	private DnsLookupHandler mockDnsLookupHandler;
	
	@Before
	public void setUp() throws Exception {
		mockDnsLookupHandler = mock(DnsLookupHandler.class);
		
		anonymiser = new SpatineoLogAnalysisIpAddressAnonymiser();
		anonymiser.setDnsLookupHandler(mockDnsLookupHandler);
		
		anonymiser.setIpv4BitsToAnonymize(8);
		anonymiser.setIpv6BitsToAnonymize(80);
	}

	@Test
	public void testBasicAnonymisationDNSLookupSuccess() throws Exception {
		DnsLookupResult mockResult = new DnsLookupResult();
		mockResult.setReverseName("hello.world.com");
		mockResult.setSuccess(true);
		when(mockDnsLookupHandler.lookup("10.10.10.10")).thenReturn(mockResult);
		
		String result = anonymiser.processAddressString("10.10.10.10");
		
		assertEquals("{!1{10.10.10.0/24,world.com}}", result);
	}
	
	@Test
	public void testBasicAnonymisationNoReverseDNS() throws Exception {
		DnsLookupResult mockResult = new DnsLookupResult();
		mockResult.setReverseName(null);
		mockResult.setSuccess(false);
		when(mockDnsLookupHandler.lookup("10.10.10.10")).thenReturn(mockResult);
		
		String result = anonymiser.processAddressString("10.10.10.10");
		
		assertEquals("{!1{10.10.10.0/24}}", result);
	}

	@Test
	public void testBasicAnonymisationDNSGivesWeirdName() throws Exception {
		DnsLookupResult mockResult = new DnsLookupResult();
		mockResult.setReverseName("124.0/25.8.118.188.in-addr.arpa");
		mockResult.setSuccess(true);
		when(mockDnsLookupHandler.lookup("10.10.10.10")).thenReturn(mockResult);
		
		String result = anonymiser.processAddressString("10.10.10.10");
		
		// Expect to have no DNS name
		assertEquals("{!1{10.10.10.0/24}}", result);
	}

	@Test
	public void testBasicAnonymisationDNSGivesLocalAddressLocalNamesAreDisabled() throws Exception {
		DnsLookupResult mockResult = new DnsLookupResult();
		mockResult.setReverseName("foo.hello.local");
		mockResult.setSuccess(true);
		when(mockDnsLookupHandler.lookup("10.10.10.10")).thenReturn(mockResult);
		
		String result = anonymiser.processAddressString("10.10.10.10");
		
		// Expect to have no DNS name since local names are disabled
		assertEquals("{!1{10.10.10.0/24}}", result);
	}

	@Test
	public void testBasicAnonymisationDNSGivesLocalAddressLocalNamesAreEnabled() throws Exception {
		
		anonymiser.setAllowFullPrivateAddresses(true);
		
		DnsLookupResult mockResult = new DnsLookupResult();
		mockResult.setReverseName("foo.hello.local");
		mockResult.setSuccess(true);
		when(mockDnsLookupHandler.lookup("10.10.10.10")).thenReturn(mockResult);
		
		String result = anonymiser.processAddressString("10.10.10.10");
		
		// Expect to have full DNS name since local names are enabled
		assertEquals("{!1{10.10.10.0/24,foo.hello.local}}", result);
	}


}
