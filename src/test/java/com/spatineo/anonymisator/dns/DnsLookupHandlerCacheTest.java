package com.spatineo.anonymisator.dns;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;

import com.spatineo.anonymisator.AnonymiserConfiguration;


public class DnsLookupHandlerCacheTest {
	private DnsjavaLookupHandlerImpl cachingLookupHandler;
	
	@Before
	public void setUp() throws Exception {
		AnonymiserConfiguration configuration = new AnonymiserConfiguration();
		configuration.setParallelThreads(1);
		
		cachingLookupHandler = new DnsjavaLookupHandlerImpl();
		cachingLookupHandler.setMaxCacheSize(10);
		cachingLookupHandler.setAnonymiserConfiguration(configuration);
		
		cachingLookupHandler.setResolver(mock(Resolver.class));
		
		cachingLookupHandler.afterPropertiesSet();
	}
	

	@Test
	public void testExpectedResult() throws Exception {
		Message ret = mock(Message.class);
		when(ret.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{});
		
		when(cachingLookupHandler.getResolver().send(any(Message.class))).thenReturn(ret);
		DnsLookupResult result = cachingLookupHandler.lookup("10.10.10.1");
		
		
		assertNotNull(result);
		assertFalse(result.isSuccess());
		verify(cachingLookupHandler.getResolver(), times(1)).send(any(Message.class));
	}



	@Test
	public void testCachingWorks() throws Exception {
		Message ret = mock(Message.class);
		when(ret.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{});
		
		when(cachingLookupHandler.getResolver().send(any(Message.class))).thenReturn(ret);
		DnsLookupResult result1 = cachingLookupHandler.lookup("10.10.10.1");
		
		DnsLookupResult result2 = cachingLookupHandler.lookup("10.10.10.1");
		
		assertSame(result1, result2);
		verify(cachingLookupHandler.getResolver(), times(1)).send(any(Message.class));
	}


	@Test
	public void testReverseWorks() throws Exception {
		Message ret = mock(Message.class);
		Record [] responseRecords = new Record[1];
		responseRecords[0] = mock(Record.class);
		when(responseRecords[0].rdataToString()).thenReturn("host.name.com.");
		
		when(ret.getSectionArray(Section.ANSWER)).thenReturn(responseRecords);
		
		when(cachingLookupHandler.getResolver().send(any(Message.class))).thenReturn(ret);
		DnsLookupResult result = cachingLookupHandler.lookup("10.10.10.1");
		
		assertTrue(result.isSuccess());
		assertEquals("host.name.com", result.getReverseName());
	}


}
