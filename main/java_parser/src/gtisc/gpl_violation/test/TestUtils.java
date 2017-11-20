package gtisc.gpl_violation.test;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import gtisc.gpl_violation.ClassSignatures;
import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.ClassSig.BasicBlockProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassAttributeProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassRelationProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassRelationProto.RelationCounter;
import gtisc.gpl_voilation.proto.ClassSig.MethodAttributeProto;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig.InputType;

public class TestUtils {
	public static Map<String, Set<String>> getClassAndMethodsMapping(AllClassesSummary result) {
		// Maps Class name string to Method signature string set
		Map<String, Set<String>> classAndMethods = new HashMap<String, Set<String>>();
		for (ClassAttributeProto cp : result.getClassesList()) {
			Set<String> methodNameSet = new HashSet<String>();
			for (MethodAttributeProto mp : cp.getMethodsList()) methodNameSet.add(mp.getMethodSignature());
			classAndMethods.put(cp.getClassName(), methodNameSet);
		}
		return classAndMethods;
	}

	public static Map<String, List<?>> getMethodSignatureAndCentroidMapping(AllClassesSummary result) {
		return getMethodSignatureAndCentroidMapping(result, false);
	}
	
	public static Map<String, List<?>> getMethodSignatureAndCentroidMapping(AllClassesSummary result, boolean useMethodName) {
		Map<String, List<?>> methodAndCentroids = new HashMap<String, List<?>>();
		for (ClassAttributeProto cp : result.getClassesList()) {
			for (MethodAttributeProto mp : cp.getMethodsList()) {
				String key =  useMethodName? mp.getMethodName(): mp.getMethodSignature();
				methodAndCentroids.put(key, Arrays.asList(
						mp.getCentroid().getX(), mp.getCentroid().getY(), mp.getCentroid().getZ(), mp.getCentroid().getW(),
						mp.getCentroidWithInvoke().getX(), mp.getCentroidWithInvoke().getY(),
						mp.getCentroidWithInvoke().getZ(), mp.getCentroidWithInvoke().getW()));
			}
		}
		return methodAndCentroids;
	}

	public static Map<String, Integer> getMethodSignatureAndBasicBlockCountMapping(AllClassesSummary result) {
		return getMethodSignatureAndBasicBlockCountMapping(result, false); 
	}
	
	public static Map<String, Integer> getMethodSignatureAndBasicBlockCountMapping(AllClassesSummary result, boolean useMethodName) {
		Map<String, Integer> methodAndBlockCount = new HashMap<String, Integer>();
		for (ClassAttributeProto cp : result.getClassesList()) {
			for (MethodAttributeProto mp : cp.getMethodsList()) {
				String key =  useMethodName? mp.getMethodName(): mp.getMethodSignature();
				methodAndBlockCount.put(key, mp.getBlocksList().size());
			}
		}
		return methodAndBlockCount;
	}		
	
	public static Map<String, List<BasicBlockProto>> getMethodSignatureAndBasicBlockMapping(AllClassesSummary result) {
		return getMethodSignatureAndBasicBlockMapping(result, false);
	}
	
	public static Map<String, List<BasicBlockProto>> getMethodSignatureAndBasicBlockMapping(AllClassesSummary result, boolean useMethodName) {
		Map<String, List<BasicBlockProto>> methodAndBlocks = new HashMap<String, List<BasicBlockProto>>();
		for (ClassAttributeProto cp : result.getClassesList()) {
			for (MethodAttributeProto mp : cp.getMethodsList()) {
				String key =  useMethodName? mp.getMethodName(): mp.getMethodSignature();
				methodAndBlocks.put(key, mp.getBlocksList());
			}
		}
		return methodAndBlocks;
	}
	
	
	public static Map<String, List<RelationCounter>> getClassPairRelationMapping(AllClassesSummary result) {
		Map<String, List<RelationCounter>> classPairAndRelations = new HashMap<String, List<RelationCounter>> ();
		for (ClassRelationProto crp : result.getClassPairsList()) {
			classPairAndRelations.put(crp.getClassname1() + "," + crp.getClassname2(), crp.getRelationCountersList());
		}
		return classPairAndRelations;
	}
	
	public static Map<String, Set<String>> getClassPairPermissionMapping(AllClassesSummary result) {
		Map<String, Set<String>> classPairAndPermissions = new HashMap<String,  Set<String>>();
		for (ClassRelationProto crp : result.getClassPairsList()) {
			classPairAndPermissions.put(crp.getClassname1() + "," + crp.getClassname2(),
					new HashSet<String>(crp.getClassname2PermissionsList()));
		}
		return classPairAndPermissions;
	}
	
	/**
	 * Check the processed result is equal to the expected result. Used in integration test.
	 * @param expected
	 * @param result
	 */
	public static void assertSummaryEquals(AllClassesSummary expected, AllClassesSummary result) {
		assertSummaryEquals(expected, result, false);
	}
	
	public static void assertSummaryEquals(AllClassesSummary expected, AllClassesSummary result, boolean checkBasicBlock) {
		// Same number of classes
		assertEquals(expected.getClassesCount(), result.getClassesCount());
		// Same class to method mapping
		assertEquals(getClassAndMethodsMapping(expected), getClassAndMethodsMapping(result));
		// Same number of class relationships
		// HACK: XXX
		Map<String, List<RelationCounter>> expectedClassPairs = getClassPairRelationMapping(expected);
		Map<String, List<RelationCounter>> resultClassPairs = getClassPairRelationMapping(result);
		if (expectedClassPairs.keySet().size() != resultClassPairs.keySet().size()) {
			Set<String> expectedSpecific = new HashSet<String>(expectedClassPairs.keySet());
			expectedSpecific.removeAll(resultClassPairs.keySet());
			System.out.println("Expected specific class pairs: " + expectedSpecific);
			Set<String> resultSpecific = new HashSet<String>(resultClassPairs.keySet());
			resultSpecific.removeAll(expectedClassPairs.keySet());			
			System.out.println("Result specific class pairs: " + resultSpecific);
		}
		assertEquals(expected.getClassPairsCount(), result.getClassPairsCount());
		// Same class pair to relationship counter mapping
		assertEquals(getClassPairRelationMapping(expected), getClassPairRelationMapping(result));
		// Same class pair to permission set mapping
		assertEquals(getClassPairPermissionMapping(expected), getClassPairPermissionMapping(result));
		if (checkBasicBlock) {
			// same number of basic blocks!
			Map<String, Integer> expectedBBCount = getMethodSignatureAndBasicBlockCountMapping(expected);
			Map<String, Integer> resultBBCount = getMethodSignatureAndBasicBlockCountMapping(result);
			for (String methodSig: expectedBBCount.keySet()) {
				assertEquals(true, resultBBCount.containsKey(methodSig));
				assertEquals(methodSig + "=" + expectedBBCount.get(methodSig), methodSig + "=" + resultBBCount.get(methodSig));
			}
			// assertEquals(getMethodSignatureAndBasicBlockCountMapping(expected), getMethodSignatureAndBasicBlockCountMapping(result));
			
			// Same value of Centroid!
			Map<String, List<?>> expectedCentroidMapping = getMethodSignatureAndCentroidMapping(expected);
			Map<String, List<?>> resultCentroidMapping = getMethodSignatureAndCentroidMapping(result);
			for (String methodSig: expectedCentroidMapping.keySet()) {
				assertEquals(true, resultCentroidMapping.containsKey(methodSig));
				assertEquals(methodSig + "=" + expectedCentroidMapping.get(methodSig), methodSig + "=" + resultCentroidMapping.get(methodSig));
			}
			// assertEquals(getMethodSignatureAndCentroidMapping(expected), getMethodSignatureAndCentroidMapping(result));
		}
	}
	
	/**
	 * Check the class to permission mapping is correct. Used in permission test.
	 * @param expected The expected class name to permission string set mapping
	 * @param real The real result
	 * @param partiallyExamine Only check that expected key/results are matching real key/results, skip the unmatched keys. 
	 */
	public static void assertPermissionEquals(Map<String, Set<String>> expected, AllClassesSummary result,
			boolean partiallyExamine) {
		Map<String, Set<String>> actualMapping = new HashMap<String, Set<String>>();
		for (ClassAttributeProto cp : result.getClassesList()) {
			if (partiallyExamine && !expected.containsKey(cp.getClassName())) continue;
			actualMapping.put(cp.getClassName(), new HashSet<String>(cp.getPermissionStringsList()));
		}
		assertEquals(expected, actualMapping);
	}
	
	public static AllClassesSummary getSummaryForTestdata(String inputPath, InputType inputType, 
			boolean useAndroidJar, boolean outputToTmp, int threadNum, boolean consolePrint) throws Exception {
		// Get the summary and check that some attributes are there.
		soot.G.reset();
		JobConfig.Builder config = JobConfig.newBuilder();
		config.setInputType(inputType);
		config.setInputPath(inputPath);
		config.setConsolePrint(consolePrint);
		if (useAndroidJar) {
			config.setAndroidJarDirPath("platforms");
			// Different android.jar version yields different analysis results
			config.setForceAndroidJarPath(config.getAndroidJarDirPath() + "/android-21/android.jar");			
		}
		if (outputToTmp) {
			config.setResultDir("/tmp");
		}
		if (threadNum > 0) {
			config.setThreadNum(threadNum);
		}
		JobConfig realConfig = config.build();
		ClassSignatures cs = new ClassSignatures(); 
		cs.setJobConfig(realConfig);
		cs.setSootOptions();
		return cs.analyze();
	}
}
