package gtisc.gpl_violation.test;

import java.io.File;

import org.junit.Test;

import gtisc.gpl_violation.util.ProtoBufferUtil;
import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig.InputType;

public class TestThreadNumberOption {
	
	private void testThreadConsistencyAndPerformance(String inputPath, InputType inputType, String expectedPath,
			boolean useAndroidJar, boolean outputToTmp) throws Exception {
		// No thread number option was tested elsewhere. Here we only test the time for different values of thread_num.
		long t1 = System.currentTimeMillis();
		AllClassesSummary slowSummary = TestUtils.getSummaryForTestdata(inputPath, inputType, 
				useAndroidJar, outputToTmp, 2, true);
		long t2 = System.currentTimeMillis();		
		AllClassesSummary fastSummary = TestUtils.getSummaryForTestdata(inputPath, inputType, 
				useAndroidJar, outputToTmp, 8, true);
		long t3 = System.currentTimeMillis();
		TestUtils.assertSummaryEquals(
				(AllClassesSummary) ProtoBufferUtil.loadFromFile(AllClassesSummary.getDefaultInstance(),
						new File(expectedPath), false),
				slowSummary);
		TestUtils.assertSummaryEquals(
				(AllClassesSummary) ProtoBufferUtil.loadFromFile(AllClassesSummary.getDefaultInstance(),
						new File(expectedPath), false),
				fastSummary);
		System.out.println("2 thread uses " + (t2 - t1) + " milliseconds");
		System.out.println("8 thread uses " + (t3 - t2) + " milliseconds");
		// this may not be true, because the processing time depends on file size and many other things.
		//assertEquals(true, t3 - t2 <= t2 - t1);
	}

	@Test
	public void testServerSocketPiiFlow() throws Exception {
		testThreadConsistencyAndPerformance("testdata/ServerSocket.pii_flow.v3.apk", JobConfig.InputType.APK,
				"testdata/ServerSocket.pii_flow.v3.apk.sig", true, false);
	}
	
	@Test
	public void testInterfaceInnerMain() throws Exception {
		testThreadConsistencyAndPerformance("testdata/TestInterfaceInnerMain.jar", JobConfig.InputType.JAR,
				"testdata/TestInterfaceInnerMain.jar.sig", false, false);
	}
}
