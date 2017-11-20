package gtisc.gpl_violation.test;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.ClassSig.BasicBlockProto;
import gtisc.gpl_voilation.proto.ClassSig.ClassAttributeProto;
import gtisc.gpl_voilation.proto.ClassSig.MethodAttributeProto;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;

public class TestBasicBlockProcessing {
	AllClassesSummary summary;
	Map<String, List<BasicBlockProto>> method2blocks;

	@Before
	public void setUp() {
		try {
			summary = TestUtils.getSummaryForTestdata("testdata/TestBasicBlock.jar", JobConfig.InputType.JAR, 
					false, false, -1, false);
			method2blocks = TestUtils.getMethodSignatureAndBasicBlockMapping(summary, true);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private BasicBlockProto getBlockBySequenceNumber(List<BasicBlockProto> blocks, int sequenceNumber) {
		for (BasicBlockProto b: blocks) {
			if (b.getSequenceNumber() == sequenceNumber) {
				return b;
			}
		}
		return null;
	}
	
	@Test
	public void testSequenceNumber () {
		List<BasicBlockProto> testLoopLevelsBlocks = method2blocks.get("testLoopLevels");
		// there are 13 blocks in total
		assertEquals(13, testLoopLevelsBlocks.size());
		List<Integer> secondBlockSuccs = getBlockBySequenceNumber(testLoopLevelsBlocks, 2).getSuccessorsList();
		// the second block points to the last block, because it dominates the second block!
		assertEquals(true, secondBlockSuccs.contains(3));
		assertEquals(true, secondBlockSuccs.contains(13));
	}

	@Test
	public void testInOutDegree () {
		List<BasicBlockProto> testSwitchBlocks = method2blocks.get("testSwitch");
		// there are 7 blocks in total
		assertEquals(7, testSwitchBlocks.size());
		// the first block is the switch block, and it has 5 branches, i.e. 5 successors!
		assertEquals(5, getBlockBySequenceNumber(testSwitchBlocks, 1).getSuccessorsCount());
		// the last block is the end block, also with 5 branches
		assertEquals(5, getBlockBySequenceNumber(testSwitchBlocks, 7).getPredecessorsCount());
	}

	@Test
	public void testLoopDepth () {
		// Method 2 loop count!
		Map<String, Integer> method2LoopCount = new HashMap<String, Integer>();
		Map<String, Map<Integer, Integer>> method2LoopDepthCounter = new HashMap<String, Map<Integer, Integer>>();
		for (ClassAttributeProto cap: summary.getClassesList()) {
			for (MethodAttributeProto mp: cap.getMethodsList()) {
				int maxLoopDepth = 0;
				Map<Integer, Integer> tmpLoopDepthCounter = new HashMap<Integer, Integer>();
				for (BasicBlockProto bbp: mp.getBlocksList()) {
					if (bbp.getLoopDepth() > maxLoopDepth) maxLoopDepth = bbp.getLoopDepth();
					tmpLoopDepthCounter.put(bbp.getLoopDepth(), 
							tmpLoopDepthCounter.getOrDefault(bbp.getLoopDepth(), 0) + 1);
				}
				method2LoopCount.put(mp.getMethodName(), maxLoopDepth);
				method2LoopDepthCounter.put(mp.getMethodName(), tmpLoopDepthCounter);
			}
		}
		
		// Check the method to loop count mapping!
		Map<String, Integer> expectedMethod2LoopCount = new HashMap<String, Integer>();
		expectedMethod2LoopCount.put("testLoopLevels", 4);
		expectedMethod2LoopCount.put("testIfElse", 0);
		expectedMethod2LoopCount.put("testSwitch", 0);
		expectedMethod2LoopCount.put("passTheCourse", 0);
		expectedMethod2LoopCount.put("testException", 0);
		expectedMethod2LoopCount.put("testIntegration", 2);
		expectedMethod2LoopCount.put("<init>", 0);
		assertEquals(expectedMethod2LoopCount, method2LoopCount);
		
		// Check the important method to loop depth mapping!
		// method testLoopLevels, should have depth 0, 1, 2, 3, 4
		Map<Integer, Integer> expectedCounterLoopLevels = new HashMap<Integer, Integer>();
		expectedCounterLoopLevels.put(0, 2);
		expectedCounterLoopLevels.put(1, 3);
		expectedCounterLoopLevels.put(2, 3);
		expectedCounterLoopLevels.put(3, 4);
		// the break block is moved outside the loop
		expectedCounterLoopLevels.put(4, 1);
		assertEquals(expectedCounterLoopLevels, method2LoopDepthCounter.get("testLoopLevels"));
		
		// method testIntegration should have depth 1, 2
		Map<Integer, Integer> expectedCounterIntegration = new HashMap<Integer, Integer>();
		expectedCounterIntegration.put(0, 2);
		expectedCounterIntegration.put(1, 16);
		expectedCounterIntegration.put(2, 11);
		assertEquals(expectedCounterIntegration, method2LoopDepthCounter.get("testIntegration"));
	}	
	@Test
	public void testStmtCount () {
		List<BasicBlockProto> testSwitchBlocks = method2blocks.get("testSwitch");
		Map<Integer, Integer> block2StmtCount =  new HashMap<Integer, Integer>();
		for (BasicBlockProto bbp: testSwitchBlocks) block2StmtCount.put(bbp.getSequenceNumber(), bbp.getStmtCount());
		Map<Integer, Integer> expectedBlock2StmtCount = new HashMap<Integer, Integer>();
		expectedBlock2StmtCount.put(1, 3);
		expectedBlock2StmtCount.put(2, 4);
		expectedBlock2StmtCount.put(3, 4);
		expectedBlock2StmtCount.put(4, 4);
		expectedBlock2StmtCount.put(5, 4);		
		expectedBlock2StmtCount.put(6, 3);
		expectedBlock2StmtCount.put(7, 2);
		assertEquals(expectedBlock2StmtCount, block2StmtCount);
	}	
	
	@Test
	public void testCentroid () {
		Map<String, List<?>> centroidMapping = TestUtils.getMethodSignatureAndCentroidMapping(summary, true);
		assertEquals(Arrays.asList(1.0, 0.0, 0.0, 3, 1.0, 0.0, 0.0, 4), centroidMapping.get("<init>"));
		assertEquals(Arrays.asList(6.560975609756097, 1.2845528455284554, 2.5365853658536586, 123,
				6.372781065088757, 1.2307692307692308, 2.5088757396449703, 169), centroidMapping.get("testLoopLevels"));
	}
}
