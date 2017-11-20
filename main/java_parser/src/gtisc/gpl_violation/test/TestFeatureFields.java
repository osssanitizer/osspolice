package gtisc.gpl_violation.test;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.ClassSig.ClassAttributeProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassRelationProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassRelationProto.RelationCounter;
import gtisc.gpl_voilation.proto.ClassSig.ClassRelationProto.RelationType;
import gtisc.gpl_voilation.proto.ClassSig.MethodAttributeProto;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;

/**
 * Test inner class and super classes.
 * 
 * @author ruian
 *
 */
public class TestFeatureFields {
	
	private void hasRelations(List<RelationCounter> realRCs, List<RelationType> expectedRelations) {
		Set<RelationType> rt = new HashSet<RelationType>();
		for (RelationCounter rc : realRCs) {
			rt.add(rc.getRelationType());
		}
		assertEquals(true, rt.containsAll(expectedRelations));
	}

	@Test
	public void testInnerClass() {
		AllClassesSummary summary = null;
		try {
			summary = TestUtils.getSummaryForTestdata("testdata/TestInterfaceInnerMain.jar", JobConfig.InputType.JAR, 
					false, false, -1, false);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Get the inner classes.
		// InnerClass should have an outerClass named OuterClass
		for (ClassAttributeProto cp : summary.getClassesList()) {
			if (cp.getClassName() == "OuterClass$InnerClass") {
				assertEquals("OuterClass", cp.getOuterClassName());
			}
		}
		for (ClassRelationProto crp : summary.getClassPairsList()) {
			if (crp.getClassname1() == "OuterClass$InnerClass" &&
					crp.getClassname2() == "OuterClass") {
				hasRelations(crp.getRelationCountersList(), Arrays.asList(RelationType.OUTER_CLASS));
			}		
		}
	}
	
	@Test
	public void testSuperClass() {
		AllClassesSummary summary = null;
		try {
			summary = TestUtils.getSummaryForTestdata("testdata/TestInterfaceInnerMain.jar", JobConfig.InputType.JAR, 
					false, false, -1, false);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		// Examine the super classes.
		// TestInterfaceInnerMain should have a super class called SuperTestInterfaceMain
		// TestInterface should have a super class called SuperTestInterface
		for (ClassAttributeProto cp : summary.getClassesList()) {
			if (cp.getClassName() == "TestInterfaceInnerMain") {
				assertEquals("SuperTestInterfaceMain", cp.getSuperClassName());
			}
			if (cp.getClassName() == "TestInterface") {
				assertEquals("SuperTestInterface", cp.getInterfaceClassNames(0));
			}
		}
		for (ClassRelationProto crp : summary.getClassPairsList()) {
			if (crp.getClassname1() == "TestInterfaceInnerMain" &&
					crp.getClassname2() == "SuperTestInterfaceMain") {
				hasRelations(crp.getRelationCountersList(), Arrays.asList(RelationType.INHERITANCE));
			}
			if (crp.getClassname1() == "TestInterface" && crp.getClassname2() == "SuperTestInterface") {
				hasRelations(crp.getRelationCountersList(), Arrays.asList(RelationType.IMPL));
			}
		}
	}
	
	@Test
	public void testFieldConstantString() {
		AllClassesSummary summary = null;
		try {
			summary = TestUtils.getSummaryForTestdata("testdata/TestFieldConstantStr.jar", JobConfig.InputType.JAR, 
					false, false, -1, false);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		// Examine the constant string fields.
		// clinit should have these constant strings: "hello", "world", "i am testing", "test", "Static Final String"
		// main should have these constant strings: "initialize", "inside function", "hehehe", "hohoho", "hahaha", "hihihi"
		assertEquals(1, summary.getClassesCount());
		ClassAttributeProto cap = summary.getClasses(0);
		assertEquals("TestFieldConstantStr", cap.getClassName());
		Map<String, Set<String>> expectedMethods = new HashMap<String, Set<String>>();
		expectedMethods.put("<clinit>", new HashSet<String>(Arrays.asList("\"hello\"", "\"world\"", "\"i am testing\"", "\"test\"", "\"Static Final String\"")));
		expectedMethods.put("main", new HashSet<String>(Arrays.asList("\"initialize\"", "\"inside function\"", "\"hehehe\"", "\"hohoho\"", "\"hahaha\"", "\"hihihi\"")));
		expectedMethods.put("<init>", new HashSet<String>());
		Map<String, Set<String>> resultMethods = new HashMap<String, Set<String>>();
		for (MethodAttributeProto map: cap.getMethodsList()) {
			resultMethods.put(map.getMethodName(), new HashSet<String>(map.getStringConstantsList()));
		}
		assertEquals(expectedMethods, resultMethods);
	}
}
