package gtisc.gpl_violation.test;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Before;
import org.junit.Test;

import gtisc.gpl_violation.ClassSignatures;
import gtisc.gpl_violation.util.ProtoBufferUtil;
import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig.InputType;

/**
 * Test the extraction results
 * @author ruian
 *
 */
public class TestIntegration {
	// Test all the results, including ClassAttr, ClassPair, MethodProto, etc
	JobConfig.Builder config = JobConfig.newBuilder();
	String currentPath = "";

	@Before
	public void setUp() {
		Path currentRelativePath = Paths.get("");
		currentPath = currentRelativePath.toAbsolutePath().toString();
	}
	
	private void integrationTest(String inputPath, InputType inputType, String expectedPath,
			boolean useAndroidJar, boolean outputToTmp) throws Exception {
		integrationTest(inputPath, inputType, expectedPath, useAndroidJar, outputToTmp, false);
	}
	
	private void integrationTest(String inputPath, InputType inputType, String expectedPath,
			boolean useAndroidJar, boolean outputToTmp, boolean checkBasicBLock) throws Exception {
		soot.G.reset();
		config.setInputType(inputType);
		config.setInputPath(inputPath);
		if (useAndroidJar) {
			config.setAndroidJarDirPath("platforms");
			// Different android.jar version yields different analysis results
			config.setForceAndroidJarPath(config.getAndroidJarDirPath() + "/android-21/android.jar");			
		}
		if (outputToTmp) {
			config.setResultDir("/tmp");
		}
		JobConfig realConfig = config.build();
		ClassSignatures cs = new ClassSignatures(); 
		cs.setJobConfig(realConfig);
		cs.setSootOptions();
		TestUtils.assertSummaryEquals(
				(AllClassesSummary) ProtoBufferUtil.loadFromFile(AllClassesSummary.getDefaultInstance(),
						new File(expectedPath), false),
				cs.analyze(),
				checkBasicBLock);
	}
	
	@Test
	public void testJavaInterfaceInnerMain() throws Exception {
		integrationTest("testdata/testjava/", JobConfig.InputType.SOURCE, "testdata/testjava/testjava.sig",
				false, false);
		// TODO: The following test fails because source code based analysis has different results compared to jar/apks,
		// this is weird, I know.
		// In this particular case, it is because that the inherited methods are visible in jar based analysis,
		// but not visible in source code. Specifically, TestInterfaceInnerMain.superRunMain is not visible in source code.
//		TestUtils.assertSummaryEquals(
//				(AllClassesSummary) ProtoBufferUtil.loadFromFile(AllClassesSummary.getDefaultInstance(),
//						new File("testdata/TestInterfaceInnerMain.jar.sig"), false),
//				(AllClassesSummary) ProtoBufferUtil.loadFromFile(AllClassesSummary.getDefaultInstance(),
//						new File("testdata/testjava/testjava.sig"), false));
	}

	@Test
	public void testJarInterfaceInnerMain() throws Exception {
		integrationTest("testdata/TestInterfaceInnerMain.jar", JobConfig.InputType.JAR, "testdata/TestInterfaceInnerMain.jar.sig",
				false, false);
	}

	@Test
	public void testJarFieldConstantStr() throws Exception {
		integrationTest("testdata/TestFieldConstantStr.jar", JobConfig.InputType.JAR, "testdata/TestFieldConstantStr.jar.sig",
						false, false);
	}

	@Test
	public void testJarMcpdfWithDependencies() throws Exception {
		integrationTest("testdata/testjars/mcpdf-0.2.4-jar-with-dependencies.jar", JobConfig.InputType.JAR, "testdata/testjars/mcpdf-0.2.4-jar-with-dependencies.jar.sig",
				false, false);
	}

	@Test
	public void testApkServerSocketPiiFlow() throws Exception {
		integrationTest("testdata/ServerSocket.pii_flow.v3.apk", JobConfig.InputType.APK, "testdata/ServerSocket.pii_flow.v3.apk.sig",
				true, false);
	}	
	
	@Test
	public void testDexRootTools() throws Exception {
		integrationTest("testdata/com.stericson.RootTools-classes.dex", JobConfig.InputType.DEX, "testdata/com.stericson.RootTools-classes.dex.sig",
				true, false);
	}
	
	@Test
	public void testBasicBlock() throws Exception {
		integrationTest("testdata/TestBasicBlock.jar", JobConfig.InputType.JAR, "testdata/TestBasicBlock.jar.sig",
				true, false, true);
	}
	
	@Test
	public void testMopubSDK() throws Exception {
		// previously we fail to process Mopub SDK, because of bug in retrieving Basic Block Sequence Number!
		integrationTest("testdata/testjars/mopub-sdk-4.4.0.jar", JobConfig.InputType.JAR, "testdata/testjars/mopub-sdk-4.4.0.jar.sig",
				true, false, true);
	}
	
	@Test
	public void testAlawarMountainCrimeRequital() throws Exception {
		// TODO: Several methods fails to process, they seem to be caused by bugs in soot! Ignoring them now!
		integrationTest("testdata/com.alawar.MountainCrimeRequital-1024.apk", JobConfig.InputType.APK,
				"testdata/com.alawar.MountainCrimeRequital-1024.apk.sig", true, false, true);
	}

	// This one is too time consuming
//	@Test
//	public void testApkBaiduMap() throws Exception {
//		integrationTest("testdata/百度地图8.7.0.apk", JobConfig.InputType.APK, "testdata/百度地图8.7.0.apk.sig",
//				true, true);
//	}
}
