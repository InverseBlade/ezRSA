package unit_test;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import ezrsa.*;

public class EzRsaTest {
	private static EzRsa rsa = new EzRsa();

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGenerateKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetPublicKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetPrivateKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testEncryptStringKey() {
		fail("Not yet implemented");
	}

	@Test
	public void testDecrypt() {
		fail("Not yet implemented");
	}

	@Test
	public void testEncryptStringString() {
		try {
			String str = rsa.encrypt("5", "asdfasdfvf+234234");
			assertEquals("234234", str);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
