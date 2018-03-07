package com.spatineo.anonymisator.dns;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.concurrent.Future;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class ParallelDnsLookupServiceTest {
	private ParallelDnsLookupService lookupService;
	private DnsLookupHandler lookupHandler;
	
	@Before
	public void setUp() throws Exception {
		lookupService = new ParallelDnsLookupService();
		lookupService.setMaxCacheSize(10);
		lookupService.setTimeoutMillis(10000l);
		lookupService.setParallelThreads(3);
		
		lookupHandler = mock(DnsLookupHandler.class);
		lookupService.setLookupHandler(lookupHandler);
		
		lookupService.afterPropertiesSet();
	}

	@After
	public void tearDown() throws Exception {
		if (lookupService != null) {
			lookupService.destroy();
		}
	}

	@Test
	public void testExpectedResult() throws Exception {
		DnsLookupResult expected = new DnsLookupResult();
		when(lookupHandler.lookup("test1")).thenReturn(expected);
		Future<DnsLookupResult> future = lookupService.lookup("test1");
		
		DnsLookupResult result = future.get();
		
		assertEquals(expected, result);
		verify(lookupHandler, times(1)).lookup(anyString());
	}

	@Test
	public void testCachingWorks() throws Exception {
		DnsLookupResult expected = new DnsLookupResult();
		when(lookupHandler.lookup("test1")).thenReturn(expected);
		
		Future<DnsLookupResult> future1 = lookupService.lookup("test1");
		DnsLookupResult result1 = future1.get();
		assertEquals(expected, result1);
		
		
		Future<DnsLookupResult> future2 = lookupService.lookup("test1");
		DnsLookupResult result2 = future2.get();
		assertEquals(expected, result2);
		// But lookup has been done only once
		verify(lookupHandler, times(1)).lookup(anyString());
	}

}
