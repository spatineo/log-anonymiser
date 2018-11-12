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
import static org.mockito.BDDMockito.*;

import java.io.StringReader;
import java.io.StringWriter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;

import com.spatineo.anonymisator.AnonymiserProcessor;
import com.spatineo.anonymisator.ApplicationConfiguration;
import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsLookupResult;

@RunWith(SpringRunner.class)
@SpringBootTest
@Import(ApplicationConfiguration.class)
public class FullStackTest {

	@Autowired
	AnonymiserProcessor processor;

	@MockBean
	DnsLookupHandler dnsLookupHandler;

	@Before
	public void setup() {
		processor.setParallelThreads(1);
	}

	@Test
	public void testRowWithPortsAndCommas() throws Exception
	{
		DnsLookupResult localhostAddress = new DnsLookupResult();
		localhostAddress.setSuccess(true);
		localhostAddress.setReverseName("localhost"); // Note: localhost is converted internally into null (as it's a private address)

		when(dnsLookupHandler.lookup("127.0.0.1")).thenReturn(localhostAddress);
		when(dnsLookupHandler.lookup("192.168.1.72")).thenReturn(localhostAddress);
		when(dnsLookupHandler.lookup("192.168.1.123")).thenReturn(localhostAddress);

		System.out.println(processor);
		String str ="127.0.0.1:59913, 192.168.1.72:59913,127.0.0.1 192.168.1.123 - - [01/Feb/2016:21:05:40 +0000] ...";

		StringWriter out = new StringWriter();
		StringReader in = new StringReader(str);
		processor.process(in, out);

		String result = out.toString();
		if (result.endsWith("\n")) {
			result = result.substring(0, result.length()-1);
		}
		System.out.println(result);

		assertEquals("{!1{127.0.0.0/24}}:59913, {!1{192.168.1.0/24}}:59913,{!1{127.0.0.0/24}} {!1{192.168.1.0/24}} - - [01/Feb/2016:21:05:40 +0000] ...", result);
	}

	@Test
	public void testRowWithNumberLooksLikeIPBut4Digits() throws Exception
	{
		DnsLookupResult localhostAddress = new DnsLookupResult();
		localhostAddress.setSuccess(true);
		localhostAddress.setReverseName("localhost"); // Note: localhost is converted internally into null (as it's a private address)

		System.out.println(processor);
		String str ="[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.3497.0 ...";

		StringWriter out = new StringWriter();
		StringReader in = new StringReader(str);
		processor.process(in, out);

		String result = out.toString();
		if (result.endsWith("\n")) {
			result = result.substring(0, result.length()-1);
		}
		System.out.println(result);

		assertEquals("[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.3497.0 ...", result);
	}

	@Test
	public void testRowWithNumberLooksLikeIPButNotIP() throws Exception
	{
		DnsLookupResult localhostAddress = new DnsLookupResult();
		localhostAddress.setSuccess(true);
		localhostAddress.setReverseName("localhost"); // Note: localhost is converted internally into null (as it's a private address)

		when(dnsLookupHandler.lookup("8.15.1.0")).thenReturn(localhostAddress);

		System.out.println(processor);
		String str ="[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.1.0 ...";

		StringWriter out = new StringWriter();
		StringReader in = new StringReader(str);
		processor.process(in, out);

		String result = out.toString();
		if (result.endsWith("\n")) {
			result = result.substring(0, result.length()-1);
		}
		System.out.println(result);

		//The anonymiser cannot tell whether the string 8.15.1.0 is an IP address or not and thus the expected result here is that the version number is anonymised
		assertEquals("[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb {!1{8.15.1.0/24}} ...", result);
	}

}
