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

public class AnonymisatorIPv4Test {

	private AnonymiserProcessor anonymisator;

	@Before
	public void setUp() throws Exception {
		anonymisator = new AnonymiserProcessor();
		anonymisator.setIpAddressAnonymiser(new IpAddressAnonymiser() {

			@Override
			public String processAddressString(String address) {
				return "--foundit--";
			}
		});
	}

	@Test
	public void testOneAddressInMiddle() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1 world");

		assertEquals("Hello --foundit-- world", foo);
	}

	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch1() throws Exception {
		String foo = anonymisator.process("Hello foo194.100.34.1 world");

		assertEquals("Hello foo194.100.34.1 world", foo);
	}

	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch2() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1foo world");

		assertEquals("Hello 194.100.34.1foo world", foo);
	}

	@Test
	public void testAddressPartOfAnotherStringShouldNotMatch3() throws Exception {
		String foo = anonymisator.process("Hello bar194.100.34.1foo world");

		assertEquals("Hello bar194.100.34.1foo world", foo);
	}

	@Test
	public void testOneAddressAtStart() throws Exception {
		String foo = anonymisator.process("194.100.34.1 world");

		assertEquals("--foundit-- world", foo);
	}


	@Test
	public void testOneAddressAtStartWithWhitespace() throws Exception {
		String foo = anonymisator.process(" 194.100.34.1 world");

		assertEquals(" --foundit-- world", foo);
	}

	@Test
	public void testOneAddressAtEnd() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1");

		assertEquals("Hello --foundit--", foo);
	}



	@Test
	public void testOneAddressAtEndWithWhitespace() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1 ");

		assertEquals("Hello --foundit-- ", foo);
	}



	@Test
	public void testTwoAddressInMiddle() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1 10.1.1.0 world");

		assertEquals("Hello --foundit-- --foundit-- world", foo);
	}

	@Test
	public void testTwoAddressOneStartOneMiddle() throws Exception {
		String foo = anonymisator.process("194.100.34.1 hello 10.1.1.0 world");

		assertEquals("--foundit-- hello --foundit-- world", foo);
	}


	@Test
	public void testTwoAddressOneMiddleOneEnd() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1 world 10.1.1.0");

		assertEquals("Hello --foundit-- world --foundit--", foo);
	}

	@Test
	public void testTwoAddressOneStartOneEnd() throws Exception {
		String foo = anonymisator.process("194.100.34.1 hello world 10.1.1.0");

		assertEquals("--foundit-- hello world --foundit--", foo);
	}


	@Test
	public void testPortSeparatedByColon() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1:1234 world");

		// Note: ports vanished becase the IpAddressAnonymiser is supposed to handle it
		assertEquals("Hello --foundit-- world", foo);
	}


	@Test
	public void testPortSeparatedByColonCommaSeparated() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1:1234,127.0.0.1:32176 world");

		// Note: ports vanished becase the IpAddressAnonymiser is supposed to handle it
		assertEquals("Hello --foundit--,--foundit-- world", foo);
	}


	@Test
	public void testXForwardedForCommas() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1,255.255.255.255,9.1.2.3 world");

		assertEquals("Hello --foundit--,--foundit--,--foundit-- world", foo);
	}

	@Test
	public void testXForwardedForCommasWithSpacesAfterComma() throws Exception {
		String foo = anonymisator.process("Hello 194.100.34.1, 255.255.255.255, 9.1.2.3 world");

		assertEquals("Hello --foundit--, --foundit--, --foundit-- world", foo);
	}


	@Test
	public void textWeirdRowWithCommasAndColons() throws Exception {
		String foo = anonymisator.process("84.192.245.70:59913, 84.192.245.70:59913,127.0.0.1 23.97.211.140 - -");

		// Note: ports vanished becase the IpAddressAnonymiser is supposed to handle it
		assertEquals("--foundit--, --foundit--,--foundit-- --foundit-- - -", foo);
	}

	@Test
	public void testAddressInQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"127.0.0.1\" world");


		assertEquals("Hello \"--foundit--\" world", foo);
	}

	@Test
	public void testAddressWithPortInQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"127.0.0.1:1234\" world");


		assertEquals("Hello \"--foundit--\" world", foo);
	}


	@Test
	public void testAddressWithPortInStartOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"127.0.0.1:1234, stuff\" world");


		assertEquals("Hello \"--foundit--, stuff\" world", foo);
	}


	@Test
	public void testAddressInStartOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"127.0.0.1, stuff\" world");


		assertEquals("Hello \"--foundit--, stuff\" world", foo);
	}

	@Test
	public void testAddressEndOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"foo, 127.0.0.1\" world");


		assertEquals("Hello \"foo, --foundit--\" world", foo);
	}

	@Test
	public void testAddressWithPortEndOfQuotes() throws Exception {
		String foo = anonymisator.process("Hello \"foo, 127.0.0.1:1234\" world");


		assertEquals("Hello \"foo, --foundit--\" world", foo);
	}


	@Test
	public void testAddressInSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '127.0.0.1' world");


		assertEquals("Hello '--foundit--' world", foo);
	}

	@Test
	public void testAddressWithPortInSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '127.0.0.1:1234' world");


		assertEquals("Hello '--foundit--' world", foo);
	}


	@Test
	public void testAddressWithPortInStartOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '127.0.0.1:1234, stuff' world");


		assertEquals("Hello '--foundit--, stuff' world", foo);
	}


	@Test
	public void testAddressInStartOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello '127.0.0.1, stuff' world");


		assertEquals("Hello '--foundit--, stuff' world", foo);
	}

	@Test
	public void testAddressEndOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello 'foo, 127.0.0.1' world");


		assertEquals("Hello 'foo, --foundit--' world", foo);
	}

	@Test
	public void testAddressWithPortEndOfSingleQuotes() throws Exception {
		String foo = anonymisator.process("Hello 'foo, 127.0.0.1:1234' world");


		assertEquals("Hello 'foo, --foundit--' world", foo);
	}

	@Test
	public void testAddressWithAllIPStartEnd0To255() throws Exception {

		for(int i=0; i<256; i++){
			String foo = anonymisator.process("Hello 'foo, "+i+".0.0."+i+":1234' world");

			assertEquals("Hello 'foo, --foundit--' world", foo);
		}
	}

}
