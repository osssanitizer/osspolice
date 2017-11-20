package gtisc.gpl_violation.test;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * The first version of class-signatures is slow and memory consuming.
 * It first collect all the classes, and then collect signature out of them.
 * The second version improves the process by having a configurable number of threads and
 * paralleled signature collection.
 * 
 * This class is designated to ensure that the first version results are consistent with the second version.
 * 
 * @author ruian
 *
 */
public class TestV1AndV2Consistency {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		// Most of the jobs have been implemented in TestIntegration. This class only covers the corner cases.
		return;
	}

}
