package com.spatineo.anonymisator.dns;

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
