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

import org.junit.Before;
import org.junit.Test;

public class AnonymisatorIPv6Test {

	private AnonymiserProcessor anonymisator;
	
	@Before
	public void setUp() throws Exception {
		anonymisator = new AnonymiserProcessor();
		anonymisator.setIpAddressAnonymiser(new IpAddressAnonymiser() {
			
			@Override
			public String processAddressString(String address) {
				if (address.charAt(0) == 'f') {
					return "--founditX--";
				}
				return "--foundit--";
			}
		});
	}

	@Test
	public void testOneAddressInMiddle() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals("Hello --foundit-- world", foo);
	}
	
	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch1() throws Exception {
		String foo = anonymisator.process("Hello foo2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals("Hello foo2001:0db8:85a3:0000:0000:8a2e:0370:7334 world", foo);
	}
	
	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch2() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world");
		
		assertEquals("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world", foo);
	}
	
	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch3() throws Exception {
		String foo = anonymisator.process("Hello bar2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world");
		
		assertEquals("Hello bar2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world", foo);
	}

	@Test
	public void testOneAddressAtStart() throws Exception {
		String foo = anonymisator.process("2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals("--foundit-- world", foo);
	}
	
	@Test
	public void testOnlyAnAddress() throws Exception {
		String foo = anonymisator.process("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
		
		assertEquals("--foundit--", foo);
	}
	

	@Test
	public void testOneAddressAtStartWithWhitespace() throws Exception {
		String foo = anonymisator.process(" 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals(" --foundit-- world", foo);
	}

	@Test
	public void testOneAddressAtEnd() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
		
		assertEquals("Hello --foundit--", foo);
	}


	@Test
	public void testOneAddressAtEndAllUpperCase() throws Exception {
		String foo = anonymisator.process("Hello 2001:0DB8:85A3:0000:0000:8A2E:0370:7334");
		
		assertEquals("Hello --foundit--", foo);
	}



	@Test
	public void testNotReallyAnAddressTooMany16ByteParts() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234");
		
		assertEquals("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234", foo);
	}



	@Test
	public void testOneAddressAtEndWithWhitespace() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ");
		
		assertEquals("Hello --foundit-- ", foo);
	}



	@Test
	public void testTwoAddressInMiddle() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 fe80::f043:57ff:fe35:77c7 world");
		
		assertEquals("Hello --foundit-- --founditX-- world", foo);
	}
	

	@Test
	public void testTwoAddressOneStartOneMiddle() throws Exception {
		String foo = anonymisator.process("2001:0db8:85a3:0000:0000:8a2e:0370:7334 hello fe80::f043:57ff:fe35:77c7 world");
		
		assertEquals("--foundit-- hello --founditX-- world", foo);
	}
	

	@Test
	public void testTwoAddressOneMiddleOneEnd() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world fe80::f043:57ff:fe35:77c7");
		
		assertEquals("Hello --foundit-- world --founditX--", foo);
	}
	
	@Test
	public void testTwoAddressOneStartOneEnd() throws Exception {
		String foo = anonymisator.process("fe80::f043:57ff:fe35:77c7 hello world 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
		
		assertEquals("--founditX-- hello world --foundit--", foo);
	}
	

	@Test
	public void testXForwardedForCommas() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334,2001:0db8:85a3:0000:0000:8a2e:0370:7334,2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals("Hello --foundit--,--foundit--,--foundit-- world", foo);
	}
	
	@Test
	public void testXForwardedForCommasWithSpacesAfterCommas() throws Exception {
		String foo = anonymisator.process("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334, 2001:0db8:85a3:0000:0000:8a2e:0370:7334, 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world");
		
		assertEquals("Hello --foundit--, --foundit--, --foundit-- world", foo);
	}
	
	

	@Test
	public void testAddressInQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"2001:0db8:85a3:0000:0000:8a2e:0370:7334\" world");

		
		assertEquals("Hello \"--foundit--\" world", foo);
	}
	

	@Test
	public void testAddressInStartOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"2001:0db8:85a3:0000:0000:8a2e:0370:7334, stuff\" world");

		
		assertEquals("Hello \"--foundit--, stuff\" world", foo);
	}
	
	@Test
	public void testAddressEndOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"foo, 2001:0db8:85a3:0000:0000:8a2e:0370:7334\" world");

		
		assertEquals("Hello \"foo, --foundit--\" world", foo);
	}
	

	@Test
	public void testAddressInSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '2001:0db8:85a3:0000:0000:8a2e:0370:7334' world");

		
		assertEquals("Hello '--foundit--' world", foo);
	}
	

	@Test
	public void testAddressInStartOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '2001:0db8:85a3:0000:0000:8a2e:0370:7334, stuff' world");

		
		assertEquals("Hello '--foundit--, stuff' world", foo);
	}
	
	@Test
	public void testAddressEndOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello 'foo, 2001:0db8:85a3:0000:0000:8a2e:0370:7334' world");

		
		assertEquals("Hello 'foo, --foundit--' world", foo);
	}
	
}
