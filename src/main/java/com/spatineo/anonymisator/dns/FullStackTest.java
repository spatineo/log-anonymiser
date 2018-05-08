package com.spatineo.anonymisator.dns;

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

}
