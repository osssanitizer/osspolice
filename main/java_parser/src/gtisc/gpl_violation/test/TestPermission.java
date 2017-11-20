package gtisc.gpl_violation.test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import gtisc.gpl_violation.ClassSignatures;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig.InputType;

/**
 * Test whether the permissions are correctly extracted.
 * 
 * @author ruian
 *
 */
public class TestPermission {
	
	private void permissionTest(String inputPath, InputType inputType, Map<String, Set<String>> expectedSet,
			boolean useAndroidJar, boolean outputToTmp) throws Exception {
		soot.G.reset();
		JobConfig.Builder config = JobConfig.newBuilder();
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
		TestUtils.assertPermissionEquals(expectedSet, cs.analyze(), true);
	}

	@Test
	public void testServerSocketPiiFlow() throws Exception {
		// There are classes that invoked permission related APIs and are labeled with these permissions.
		Map<String, Set<String>> class2Permission = new HashMap<String, Set<String>>();
		class2Permission.put("test.app.gtisc.androidserversocket.MainActivity$SocketServerThread", 
				new HashSet<String>(Arrays.asList("android.permission.INTERNET")));
		class2Permission.put("test.app.gtisc.androidserversocket.SocketService$connectSocket",
				new HashSet<String>(Arrays.asList("android.permission.INTERNET")));
		class2Permission.put("test.app.gtisc.androidserversocket.NotUsedClass",
				new HashSet<String>(Arrays.asList("android.permission.INTERNET")));
		class2Permission.put("test.app.gtisc.androidserversocket.MainActivity",
				new HashSet<String>(Arrays.asList("android.permission.READ_PHONE_STATE")));
		class2Permission.put("test.app.gtisc.androidserversocket.NotUsedClass",
				new HashSet<String>(Arrays.asList("android.permission.INTERNET")));
		class2Permission.put("test.app.gtisc.androidserversocket.NotUsedClass",
				new HashSet<String>(Arrays.asList("android.permission.INTERNET")));
		permissionTest("testdata/ServerSocket.pii_flow.v3.apk", JobConfig.InputType.APK, class2Permission,
				true, false);
	}
}
