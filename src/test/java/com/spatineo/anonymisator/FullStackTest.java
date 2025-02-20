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

	/**
	 * The anonymiser cannot tell whether the string 8.15.1.0 is an IP address or not and thus the expected result here is that the version number is anonymised
	 */
	@Test
	public void testRowWithNumberLooksLikeIPButNotIP() throws Exception
	{
		DnsLookupResult localhostAddress = new DnsLookupResult();
		localhostAddress.setSuccess(true);
		localhostAddress.setReverseName("localhost"); // Note: localhost is converted internally into null (as it's a private address)

		when(dnsLookupHandler.lookup("8.15.1.0")).thenReturn(localhostAddress);

		String str ="[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.1.0 ...";

		StringWriter out = new StringWriter();
		StringReader in = new StringReader(str);
		processor.process(in, out);

		String result = out.toString();
		if (result.endsWith("\n")) {
			result = result.substring(0, result.length()-1);
		}
		System.out.println(result);


		assertEquals("[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb {!1{8.15.1.0/24}} ...", result);
	}

	@Test
	public void testMIISLogWithMultipleIPs() throws Exception
	{
		DnsLookupResult firstAddress = new DnsLookupResult();
		firstAddress.setSuccess(true);
		firstAddress.setReverseName("localhost"); // Note: localhost is converted internally into null (as it's a private address)


		DnsLookupResult secondAddress = new DnsLookupResult();
		secondAddress.setSuccess(true);
		secondAddress.setReverseName("foobar.com");
		
		DnsLookupResult thirdAddress = new DnsLookupResult();
		thirdAddress.setSuccess(true);
		thirdAddress.setReverseName("gah.com");
		
		when(dnsLookupHandler.lookup("8.15.1.0")).thenReturn(firstAddress);
		when(dnsLookupHandler.lookup("8.15.1.1")).thenReturn(secondAddress);
		when(dnsLookupHandler.lookup("8.15.1.2")).thenReturn(thirdAddress);

		String str ="2025-02-03 06:46:14 8.15.1.0 GET /TeklaOGCWeb/WMS.ashx LAYERS=Kantakartta&TRANSPARENT=true&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&FORMAT=image%2Fpng&cscale=50&SRS=EPSG%3A3878&BBOX=24517377.400616,6693043.2824233,24517380.787281,6693046.6690881&WIDTH=256&HEIGHT=256 443 KeyAquaRajapinta {!1{172.21.41.0/24}} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/132.0.0.0+Safari/537.36 https://vihti.keyaqua.keypro.fi/ 200 0 0 1203 8.15.1.1,+8.15.1.2";

		StringWriter out = new StringWriter();
		StringReader in = new StringReader(str);
		processor.process(in, out);

		String result = out.toString();
		if (result.endsWith("\n")) {
			result = result.substring(0, result.length()-1);
		}
		System.out.println(result);

		assertEquals("2025-02-03 06:46:14 {!1{8.15.1.0/24}} GET /TeklaOGCWeb/WMS.ashx LAYERS=Kantakartta&TRANSPARENT=true&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&FORMAT=image%2Fpng&cscale=50&SRS=EPSG%3A3878&BBOX=24517377.400616,6693043.2824233,24517380.787281,6693046.6690881&WIDTH=256&HEIGHT=256 443 KeyAquaRajapinta {!1{172.21.41.0/24}} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/132.0.0.0+Safari/537.36 https://vihti.keyaqua.keypro.fi/ 200 0 0 1203 {!1{8.15.1.0/24,foobar.com}},+{!1{8.15.1.0/24,gah.com}}", result);
	}
}
