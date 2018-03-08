package com.spatineo.anonymisator;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class AnonymisatorTest {

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
}
