package gtisc.gpl_violation;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

import gtisc.gpl_violation.permission.PSCout;
import gtisc.gpl_violation.permission.PermissionUtil;
import gtisc.gpl_violation.util.BasicBlockUtil;
import gtisc.gpl_violation.util.ClassSignaturesUtil;
import gtisc.gpl_violation.util.ProtoBufferUtil;
import gtisc.gpl_voilation.proto.ClassSig.AllClassesSummary;
import gtisc.gpl_voilation.proto.ClassSig.BasicBlockProto;
import gtisc.gpl_voilation.proto.ClassSig.MethodAttributeProto;
import gtisc.gpl_voilation.proto.JobRunner.JobConfig;
import heros.solver.CountingThreadPoolExecutor;
import soot.ArrayType;
import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.Modifier;
import soot.PackManager;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Transform;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.Expr;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceOfExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticFieldRef;
import soot.jimple.StringConstant;
import soot.toolkits.graph.Block;
import soot.util.Chain;

/**
 * Extract signatures for the given input classes. The signatures includes two parts, 
 * (1) first part is the analysis of application classes
 * (2) second part is the relationship between application classes and all other classes
 * (app & framework classes)
 * 
 * @author ruian
 */
public class ClassSignatures {
	public org.apache.commons.cli.Options options = null;
	private JobConfig config = null;	
	private PSCout psCout = null;
	
	// The output
	// maps class name to ClassAttr
	private ConcurrentMap<SootClass, ClassAttr> classAttrs = new ConcurrentHashMap<SootClass, ClassAttr>();
	// maps class pair string to ClassPair
	private ConcurrentMap<String, ClassesPair> classesPairs = new ConcurrentHashMap<String, ClassesPair>();

	private void buildOptions() {
		options = new Options();
		
		options.addOption("job", true, "the name of the job to run. Currently ignore this option!");		
		options.addOption("inputType", true, "type of input");
		options.addOption("inputPath", true, "path to input");
		options.addOption("androidJarDir", true, "android jars directory");  
		options.addOption("configPath", true, "The path to the configuration file");
		options.addOption("resultDir", true, "The directory to store the results");		
		options.addOption("sootOutDir", true, "out dir, needed in soot to produce intermediate results");
		options.addOption("consolePrint", false, "whether or not to print analysis result to terminal");
		options.addOption("binaryConfig", false, "Whether the configurations are in binary or not!");
		options.addOption("binaryOutput", false, "Whether the output should be stored in binary or not!");
		options.addOption("keepSootOutput", false, "Whether to keep the soot output or not (default false)!");
		options.addOption("threadNum", true, "The number of threads to use");
		// no androsim path, diff method path
	}
	
	public void setJobConfig(JobConfig jobConfig) {
		config = JobConfig.newBuilder(jobConfig).build();
	}
	
	public Iterable<ClassesPair> getClassesPairs() {
		return classesPairs.values();
	}
	
	public Iterable<ClassAttr> getClassAttrs() {
		return classAttrs.values();
	}

	private void parseOptions(String[] args) {
		Locale locale = new Locale("en", "US");
		Locale.setDefault(locale);

		CommandLineParser parser = new PosixParser();
		CommandLine commandLine;
		JobConfig.Builder configBuilder = JobConfig.newBuilder();

		try {
			commandLine = parser.parse(options, args);

			commandLine.getArgs();
			org.apache.commons.cli.Option[] clOptions = commandLine.getOptions();

			for (int i = 0; i < clOptions.length; i++) {
				org.apache.commons.cli.Option option = clOptions[i];
				String opt = option.getOpt();

				if (opt.equals("job")) {
					configBuilder.setJobName(commandLine.getOptionValue("job"));
				} else if (opt.equals("inputType")) {
					configBuilder.setInputType(JobConfig.InputType.valueOf(commandLine.getOptionValue("inputType")));
					if (configBuilder.getInputType() == JobConfig.InputType.APK || configBuilder.getInputType() == JobConfig.InputType.APK_DIR ||
							configBuilder.getInputType() == JobConfig.InputType.DEX || configBuilder.getInputType() == JobConfig.InputType.DEX_DIR)
						configBuilder.setExpectAndroidJar(true);
				} else if (opt.equals("inputPath")) {
					configBuilder.setInputPath(commandLine.getOptionValue("inputPath"));
				} else if (opt.equals("androidJarDir")) {
					configBuilder.setAndroidJarDirPath(commandLine.getOptionValue("androidJarDir"));
					configBuilder.setForceAndroidJarPath(configBuilder.getAndroidJarDirPath() + "/android-21/android.jar");
				} else if (opt.equals("configPath")) {
					configBuilder.setConfigPath(commandLine.getOptionValue("configPath"));
				} else if (opt.equals("resultDir")) {
					configBuilder.setResultDir(commandLine.getOptionValue("resultDir"));
				} else if (opt.equals("sootOutDir")) {
					configBuilder.setSootOutDir(commandLine.getOptionValue("sootOutDir"));
				} else if (opt.equals("consolePrint")) {
					configBuilder.setConsolePrint(true);
				} else if (opt.equals("binaryConfig")) {
					configBuilder.setBinaryConfig(true);
				} else if (opt.equals("binaryOutput")) {
					configBuilder.setBinaryOutput(true);
				} else if (opt.equals("keepSootOutput")) {
					configBuilder.setKeepSootOutput(true);
				} else if (opt.equals("threadNum")) {
					configBuilder.setThreadNum(Integer.parseInt(commandLine.getOptionValue("threadNum")));
				}
				config = configBuilder.build();
			}
		} catch (ParseException ex) {
			ex.printStackTrace();
			return;
		}
	}
	
	/**
	 * Parse arguments and call analyze().
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		// 1. enable assertion and build options
		ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);
		ClassSignatures cs = new ClassSignatures();
		
		cs.buildOptions();
		cs.parseOptions(args);
		
		// 2. set soot options
		cs.setSootOptions();
		
		// 3. call analyze
		cs.analyze();
	}
	
	/**
	 * Set soot options based on current configurations.
	 */
	public void setSootOptions() throws Exception {
		if (config.getInputType() == JobConfig.InputType.APK || config.getInputType() == JobConfig.InputType.APK_DIR) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
			// There can be multiple dex file in an APK.
			soot.options.Options.v().set_process_multiple_dex(true);			
		} else if (config.getInputType() == JobConfig.InputType.DEX || config.getInputType() == JobConfig.InputType.DEX_DIR) {
			// or normalize to jar? How do they do the dex2jar conversion
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		} else if (config.getInputType() == JobConfig.InputType.SOURCE|| config.getInputType() == JobConfig.InputType.SOURCE_DIR) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_java);
		} else if (config.getInputType() == JobConfig.InputType.CLASS || config.getInputType() == JobConfig.InputType.CLASS_DIR) {
			// https://github.com/Sable/soot/wiki/Introduction:-Soot-as-a-command-line-tool
			// only use class files
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_only_class);
		} else if (config.getInputType() == JobConfig.InputType.JAR || config.getInputType() == JobConfig.InputType.JAR_DIR) {
			soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_only_class);
		} else if (config.getInputType() == JobConfig.InputType.UNKNOWN) {
			throw new Exception ("Unknown input type");
		}
		// WARNING: we need JIMPLE output to be able to process static final fields in <clinit> methods.		
		soot.options.Options.v().set_output_format(soot.options.Options.output_format_J);
		if (config.hasThreadNum()) {
			soot.options.Options.v().set_thread_num(config.getThreadNum());
		}
		soot.options.Options.v().set_allow_phantom_refs(true);
		//soot.options.Options.v().set_whole_program(true);		
	}
	
	/**
	 * The function is the main function to extract signatures from jar/classes/apks.
	 * The global object *config* are used to perform analysis.
	 */
	public AllClassesSummary analyze() throws Exception {
		// 1. run packs
		// maps SootMethod to method bodies
		long t1 = System.currentTimeMillis();
		final ConcurrentHashMap<SootMethod, Body> bodies = new ConcurrentHashMap<SootMethod, Body>();
		
		PackManager.v().getPack("jtp").add(new Transform("jtp.classSignatures", new BodyTransformer() {
			@Override
			protected void internalTransform(Body b, String phaseName,
					Map<String, String> options) {
				
				bodies.put(b.getMethod(), b);
			}
		}));
		
		File inFile = null;
		if (config.getInputType() == JobConfig.InputType.APK_DIR || config.getInputType() == JobConfig.InputType.DEX_DIR ||
				config.getInputType() == JobConfig.InputType.SOURCE_DIR || config.getInputType() == JobConfig.InputType.CLASS_DIR ||
				config.getInputType() == JobConfig.InputType.JAR_DIR) {
			throw new Exception ("Unhandled input format");
		} else {
			inFile = new File(config.getInputPath());
		}
		String outputBasename = inFile.getName();
		int suffixIndex = outputBasename.lastIndexOf(".");
		if (suffixIndex != -1) outputBasename = outputBasename.substring(0, suffixIndex);
		String sootOutDir;
		if (config.hasSootOutDir()) sootOutDir = config.getSootOutDir() + File.separator + outputBasename;
		else sootOutDir = "/tmp" + File.separator + outputBasename;

		String[] sootArgs = null;
		if (config.hasAndroidJarDirPath()) {
			// If the input type is DEX or APK, then android jar path must exist! 
			sootArgs = new String[]{
				"-android-jars",
				config.getAndroidJarDirPath(),
				"-process-dir",
				inFile.getAbsolutePath(),
				"-d",
				sootOutDir,
				// TODO: maybe remove this if the input is not apk?
				"-force-android-jar",
				config.getForceAndroidJarPath()
			};
		} else if (config.getExpectAndroidJar()) {
			// Expect Android Jar, but doesn't have Android Jar Path
			throw new Exception("Expect Android Jar for input type, but Android Jar is not provided!");
		} else {
			sootArgs = new String[]{
				"-process-dir",
				inFile.getAbsolutePath(),
				"-d",
				sootOutDir,
			};
		}
		soot.Main.main(sootArgs);
		
		// 2. extract signatures
		long t2 = System.currentTimeMillis();
		extractSignatures(Scene.v().getClasses(), bodies);
		
		// 3. dump signatures to file
		long t3 = System.currentTimeMillis();
		AllClassesSummary summary = getAllClassesSummary();
		if (config.hasResultDir()) {
			dumpSummaryToFile(new File(config.getResultDir() + File.separator + inFile.getName() + config.getResultSuffix()),
					summary, config.getBinaryOutput());
		}
		long t4 = System.currentTimeMillis();
		if (config.getConsolePrint()) {
			System.out.println("Run packs took " + (t2 - t1) + "\n" +
							   "Extract signatures took " + (t3 - t2) + "\n" +
							   "Dump signatures to file took " + (t4 - t3) + "\n" +
							   "Total elapsed time is: " + (t4 - t1) + " milliseconds.\n");
		}
		
		// 5. remove intermediate soot output if instructed!
		if (!config.getKeepSootOutput()) FileUtils.deleteDirectory(new File(sootOutDir));
		
		return summary;
	}
	
	/**
	 * Extract the signatures of all the provided classes
	 * @param allClasses, all the classes
	 * @param bodies, all
	 */
	private void extractSignatures(Chain<SootClass> allClasses, Map<SootMethod, Body> bodies) {
		/* Invocation related, these are information that is actually invoked
		 */
		// initialize PSCout
		psCout = new PSCout(PermissionUtil.getDataDir() + File.separator + "jellybean_allmappings",
				PermissionUtil.getDataDir() + File.separator + "jellybean_intentpermissions");
		
		int threadNum = config.hasThreadNum()? config.getThreadNum() : Runtime.getRuntime().availableProcessors();
		
        CountingThreadPoolExecutor executor =  new CountingThreadPoolExecutor(threadNum,
        		threadNum, 30, TimeUnit.SECONDS,
        		new LinkedBlockingQueue<Runnable>());
    	
        Iterator<SootClass> iterClass = allClasses.iterator();
        // Improve efficiency
        final Map<String, SootClass> className2Class = new HashMap<String, SootClass>();
        for ( SootClass sc : allClasses) {
        	className2Class.put(sc.getName(), sc);
        }
    	while( iterClass.hasNext() ) {
    		final SootClass c = iterClass.next();
           	executor.execute(new Runnable() {
				
				@Override
				public void run() {
					extractSignatureWorker(className2Class, bodies, c);
				}
				
           	});
        }
    	
        // Wait till all packs have been executed
        try {
        	executor.awaitCompletion();
			executor.shutdown();
		} catch (InterruptedException e) {
			// Something went horribly wrong
			throw new RuntimeException("Could not wait for extract threads to "
					+ "finish: " + e.getMessage(), e);
		}
        
        // If something went wrong, we tell the world
        if (executor.getException() != null)
        	throw (RuntimeException) executor.getException(); 
	}  // end extractSignatures
	
	private void extractSignatureWorker(Map<String, SootClass> className2Class, Map<SootMethod, Body> bodies, SootClass sootClass) {
		if (!sootClass.isApplicationClass()) return; 
		ClassAttr classAttr = classAttrs.computeIfAbsent(sootClass, sc -> new ClassAttr(sc));
		// 1. super class, innner classes
		if (sootClass.hasSuperclass()) {
			SootClass superClass = sootClass.getSuperclass();
			if (className2Class.containsKey(superClass.getName())) {
				ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), superClass.getName(), 
						superClass.isApplicationClass(), ClassRelation.INHERITANCE.getIndex());
			}
		}
		if (sootClass.hasOuterClass()) {
			SootClass outerClass = sootClass.getOuterClass();
			ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), outerClass.getName(), 
					outerClass.isApplicationClass(), ClassRelation.OUTER_CLASS.getIndex());			
			classAttr.setOuterClassName(outerClass.getName());
		} else if (sootClass.getName().contains("$")) {
			// TODO: This is a temporary fix to the outer class relationship
			try {
				// Get the outer class, and strip trailing extra $ characters!
				String possibleOuterClass = StringUtils.stripEnd(sootClass.getName().substring(0, sootClass.getName().lastIndexOf('$')), "$");
				SootClass outerClass = Scene.v().getSootClass(possibleOuterClass);
				if (outerClass != null) { 
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), outerClass.getName(), 
							outerClass.isApplicationClass(), ClassRelation.OUTER_CLASS.getIndex());
					classAttr.setOuterClassName(outerClass.getName());
				}
			} catch (Exception e) {
				// The soot class may not exist
				// e.printStackTrace();
			}
		}
		// 2. interface
		Chain<SootClass> interfaces = sootClass.getInterfaces();		
		if (interfaces != null) {
			for (SootClass impl : interfaces) {
				if (className2Class.containsKey(impl.getName())) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), impl.getName(), 
							impl.isApplicationClass(), ClassRelation.IMPL.getIndex());
				}
			}
		}
		// 3. static & instance fields
		//static & instance fields
		for (SootField field : sootClass.getFields()) {
			Type type = field.getType();
			if (type instanceof ArrayType) {
				//array field
				ArrayType arrayType = (ArrayType) type;
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType); 
				if (typeClass != null) {
					if (field.isStatic()) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.STATIC_ARRAY_FIELD.getIndex());
					} else {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.INSTANCE_ARRAY_FIELD.getIndex());
					}
				}
			} else {
				//base type field
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
				if (typeClass != null) {
					if (field.isStatic()) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.STATIC__FIELD.getIndex());						
					} else {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.INSTANCE_FIELD.getIndex());
					}
				}
			}
		}
		
		// 4. methods, <init>, <clinit>, and other methods
		// 4.1 method prototype
		// 4.2 locals
		// 4.3 constant strings, each method, as well as in <init> and <clinit>
		// 4.4 basic block level information, including seq_num, loop_depth, in/out_degree and number of statements
		// 4.5 invoke framework APIs & permission related APIs & other classes methods & same class methods
		List<SootMethod> methods = sootClass.getMethods();
		for (SootMethod method : methods) {
			MethodAttributeProto.Builder methodProto = MethodAttributeProto.newBuilder();
			methodProto.setClassName(sootClass.getName());
			methodProto.setMethodName(method.getName());
			methodProto.setMethodSignature(method.getSignature());
			methodProto.setMethodSubsignature(method.getSubSignature());
			methodProto.setModifiers(Modifier.toString(method.getModifiers()));

			// 4.1 method prototype
			List<Type> parameterTypes = method.getParameterTypes();
			for (Type parameterType : parameterTypes) {
				methodProto.addParamterTypes(parameterType.toString());
				if (parameterType instanceof ArrayType) {
					ArrayType arrayType = (ArrayType) parameterType;
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType); 
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_PARAMERTER.getIndex());
					}
				} else {
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, parameterType);					
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_PARAMETER.getIndex());
					}
				}
			}
			Type returnType = method.getReturnType();
			methodProto.setReturnType(returnType.toString());
			if (returnType instanceof ArrayType) {
				ArrayType arrayType = (ArrayType) returnType;
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType);
				if (typeClass != null) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
							typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_RETURN.getIndex());
				}
			} else {
				SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, returnType);					
				if (typeClass != null) {
					ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
							typeClass.isApplicationClass(), ClassRelation.METHOD_RETURN.getIndex());
				}
			}
			Body body = bodies.get(method);
			if (body == null) continue;				

			// 4.2 locals
			List<Local> locals = Lists.newArrayList(body.getLocals());
			for (Local local : locals) {
				Type type = local.getType();
				methodProto.addLocalTypes(type.toString());
				if (type instanceof ArrayType) {
					ArrayType arrayType = (ArrayType) type;
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, arrayType.baseType);
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_ARRAY_LOCAL.getIndex());
					}
				} else {
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);						
					if (ClassSignaturesUtil.isTypeExist(className2Class, type)) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
								typeClass.isApplicationClass(), ClassRelation.METHOD_LOCAL.getIndex());
					}
				}
			}
			
			// 4.4 basic blocks
			// reference: http://stackoverflow.com/questions/6792305/identify-loops-in-java-byte-code
			try {
				BasicBlockUtil bbu = new BasicBlockUtil(body);
				for (Block block: bbu.getBlocks()) {
					BasicBlockProto.Builder blockProto = BasicBlockProto.newBuilder();
					blockProto.setSequenceNumber(bbu.getBlockSequenceNumber(block));
					blockProto.setInDegree(bbu.getInDegree(block));
					blockProto.setOutDegree(bbu.getOutDegree(block));
					blockProto.setInDegreeUnexceptional(bbu.getInDegreeUnexceptional(block));
					blockProto.setOutDegreeUnexceptional(bbu.getOutDegreeUnexceptional(block));
					blockProto.setLoopDepth(bbu.getLoopLevel(block));
					blockProto.setStmtCount(bbu.getStmtCount(block));
					blockProto.addAllPredecessors(bbu.getPredecessors(block));
					blockProto.addAllSuccessors(bbu.getSuccessors(block));
					for (SootMethod blockInvokeMethod: bbu.getInvokeMethods(block)) {
						blockProto.addInvokedMethodSignatures(blockInvokeMethod.getSignature());
					}
					int dominatorSeqNum = bbu.getDominatorSequenceNumber(block);
					if (dominatorSeqNum != -1)  blockProto.setDominatorSequenceNumber(dominatorSeqNum);
					// blockProto.setBlockContent(block.toString());
					methodProto.addBlocks(blockProto.build());
				}
				// calculate Centroid and Centroid with Invoke
				BasicBlockUtil.computeAndSetCentroid(methodProto);
			} catch (Exception e) {
				System.out.println("Exception failed to compute basic block information for :" + body.getMethod());
				e.printStackTrace();
			} catch (Error e) {
				System.out.println("Error failed to compute basic block information for :" + body.getMethod() + ", Ignoring!");
				e.printStackTrace();
			}
			
			// 4.3/4.5: iterate through each unit to find: constant strings, invoke expressions
			// Analyze whether the invoke expression is permission related or framework related
			PatchingChain<Unit> units = body.getUnits();
			for (Iterator<Unit> iter = units.iterator(); iter.hasNext();) {
				Unit unit = iter.next();
				if (unit instanceof AssignStmt) {
					AssignStmt assignStmt = (AssignStmt) unit;
					Value lV = assignStmt.getLeftOp();
					Value rV = assignStmt.getRightOp();
					
					ArrayList<Value> tmpVs = new ArrayList<Value>();
					tmpVs.add(lV);
					tmpVs.add(rV);
					for (Value tmpV : tmpVs) {
						if (tmpV instanceof Local) {
							Local local = (Local) tmpV;
							Type type = local.getType();
							if (type instanceof ArrayType) {
								ArrayType arrayType = (ArrayType) type;
								type = arrayType.baseType;
							}
							SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
							if (typeClass != null) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
										typeClass.isApplicationClass(), ClassRelation.STMT_LOCAL_REF.getIndex());
							}
						} else if (tmpV instanceof ArrayRef) {
							ArrayRef arrayRef = (ArrayRef) tmpV;
							Type type = arrayRef.getBase().getType();
							if (type instanceof ArrayType) {
								ArrayType arrayType = (ArrayType) type;
								type = arrayType.baseType;
							}
							SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
							if (typeClass != null) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), 
										typeClass.isApplicationClass(), ClassRelation.STMT_ARRAY_REF.getIndex());
							}
						} else if (tmpV instanceof StaticFieldRef) {
							StaticFieldRef staticFieldRef = (StaticFieldRef) tmpV;
							// If the referenced field is resource, we want to list them.
							SootField field = staticFieldRef.getField();
							if (field.toString().startsWith("R.")) {
								methodProto.addResourceRefs(field.toString());
							}
							SootClass varClass = field.getDeclaringClass();
							if (className2Class.containsKey(varClass.getName())) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), varClass.getName(), 
										varClass.isApplicationClass(), ClassRelation.STMT_STATIC_FIELD_REF.getIndex());
							}
						} else if (tmpV instanceof InstanceFieldRef) {
							InstanceFieldRef instanceFieldRef = (InstanceFieldRef) tmpV;
							SootClass varClass = instanceFieldRef.getField().getDeclaringClass();
							if (className2Class.containsKey(varClass.getName())) {
								ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(), varClass.getName(), 
										varClass.isApplicationClass(), ClassRelation.STMT_INSTANCE_FIELD_REF.getIndex());
							}
						} else if (tmpV instanceof StringConstant) {
							/**
							 * AssignStmt, rightOp, can be a StringConstant
							 */
							StringConstant strConst = (StringConstant) tmpV;
							methodProto.addStringConstants(strConst.toString());
						} else if (tmpV instanceof Expr) {
							/**
							 * The interesting expressions are:
							 * CastExpr, InstanceOfExpr, NewExpr, NewMultiArray, NewArray, InvokeExpr
							 * 
							 * InvokeExpr, arg can be a StringConstant
							 */
							if (tmpV instanceof CastExpr) {
								CastExpr castExpr = (CastExpr) tmpV;
								Type type = castExpr.getCastType();
								Type immType = castExpr.getOp().getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								if (immType instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) immType;
									immType = arrayType.baseType;
								}
								SootClass toClass = ClassSignaturesUtil.getTypeClass(className2Class, immType);
								SootClass fromClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (toClass != null && fromClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, toClass.getName(),
											fromClass.getName(), fromClass.isApplicationClass(), ClassRelation.CAST_EXPR.getIndex());
								}
							} else if (tmpV instanceof InstanceOfExpr) {
								InstanceOfExpr instanceOfExpr = (InstanceOfExpr) tmpV;
								Type type = instanceOfExpr.getCheckType();
								Type immType = instanceOfExpr.getOp().getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								if (immType instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) immType;
									immType = arrayType.baseType;
								}
								SootClass toClass = ClassSignaturesUtil.getTypeClass(className2Class, immType);
								SootClass fromClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (toClass != null && fromClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, toClass.getName(),
											fromClass.getName(), fromClass.isApplicationClass(), ClassRelation.INSTANCE_OF_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewExpr) {
								NewExpr newExpr = (NewExpr) tmpV;
								Type type = newExpr.getType();
								if (type instanceof ArrayType) {
									ArrayType arrayType = (ArrayType) type;
									type = arrayType.baseType;
								}
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewMultiArrayExpr) {
								NewMultiArrayExpr newMultiArrayExpr = (NewMultiArrayExpr) tmpV;
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, newMultiArrayExpr.getBaseType().baseType);
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_MULTI_ARRAY_EXPR.getIndex());
								}
							} else if (tmpV instanceof NewArrayExpr) {
								NewArrayExpr newArrayExpr = (NewArrayExpr) tmpV;
								SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, newArrayExpr.getBaseType());
								if (typeClass != null) {
									ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
											typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.NEW_ARRAY_EXPR.getIndex());
								}
							} else if (tmpV instanceof InvokeExpr) {
								handleInvokeExpr((Expr) tmpV, sootClass, classAttr, methodProto, className2Class);
							} 
						}
					}
				} else if (unit instanceof InvokeStmt) {
					/**
					 * InvokeStmt, arg can be a StringConstant
					 */
					InvokeStmt invokeStmt = (InvokeStmt) unit;
					InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
					handleInvokeExpr((Expr) invokeExpr, sootClass, classAttr, methodProto, className2Class);
				} else if (unit instanceof ReturnStmt) {
					/**
					 * ReturnStmt, returnOp can be a StringConstant
					 */
					ReturnStmt returnStmt = (ReturnStmt) unit;
					if (returnStmt.getOp() instanceof StringConstant)
						methodProto.addStringConstants(returnStmt.getOp().toString());
					Type type = returnStmt.getOp().getType();
					if (type instanceof ArrayType) {
						ArrayType arrayType = (ArrayType) type;
						type = arrayType.baseType;
					}
					SootClass typeClass = ClassSignaturesUtil.getTypeClass(className2Class, type);
					if (typeClass != null) {
						ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
								typeClass.getName(), typeClass.isApplicationClass(), ClassRelation.STMT_LOCAL_REF.getIndex());
					}
				} else {
					if (config.getConsolePrint()) System.out.println("Unknown unit type: " + unit.getClass().getName());
				}
		
			}
			// Update the methodProto
			classAttr.addMethodProto(methodProto.build());
		}  // end method iteration
	}
	
	private void handleInvokeExpr(Expr expr, SootClass sootClass, ClassAttr classAttr,
			MethodAttributeProto.Builder methodProto, Map<String, SootClass> allClasses) {
		InvokeExpr invokeExpr = (InvokeExpr) expr;
		
		SootMethod targetMethod = null;
		try {
			targetMethod = invokeExpr.getMethod();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (targetMethod == null) {
			return;
		}
		SootClass targetClass = targetMethod.getDeclaringClass();
		if (allClasses.containsKey(targetClass.getName())) {
			// NOTE: Invoked signature is already recorded in BasicBlock, get rid of this information to save space!
			// methodProto.addInvokedMethodSignatures(targetMethod.getSignature());
			
			// Update invoke information and permission information for ClassAttr
			if (!targetClass.isApplicationClass()) {
				classAttr.addSysCallStr(targetMethod.getSignature());
			}
			String targetMethodName = targetClass.getName()+ "." + targetMethod.getName();		
			String permission = psCout.getApiPermission(targetMethodName);
			if (permission != null) {
				classAttr.addPermissionStr(permission);
			}
			// Update invoke relationship and permission for ClassPair
			ClassSignaturesUtil.updateClassesPair(classesPairs, sootClass.getName(),
					targetClass.getName(), targetClass.isApplicationClass(), ClassRelation.INVOKE_EXPR.getIndex(),
					permission);
		}		
		
		List<Value> mArgs = invokeExpr.getArgs();
		for (Value arg : mArgs) {
			if (arg instanceof StringConstant)
				methodProto.addStringConstants(arg.toString());
			Type type = arg.getType();
			if (type instanceof ArrayType) {
				ArrayType arrayType = (ArrayType) type;
				type = arrayType.baseType;
			}
			SootClass typeClass = ClassSignaturesUtil.getTypeClass(allClasses, type);
			if (typeClass != null) {
				ClassesPair pair = ClassSignaturesUtil.getClassesPair(classesPairs, sootClass.getName(), typeClass.getName(), typeClass.isApplicationClass());
				pair.relationNums[ClassRelation.STMT_LOCAL_REF.getIndex()] += 1;
			}
		}
	}
	
	private AllClassesSummary getAllClassesSummary() {
		AllClassesSummary.Builder summary = AllClassesSummary.newBuilder();
		summary.setInputPath(config.getInputPath());
		for (ClassAttr classAttr : classAttrs.values()) {
			summary.addClasses(classAttr.toProto());
		}
		for (ClassesPair pair : classesPairs.values()) {
			summary.addClassPairs(pair.toProto());
		}
		return summary.build();
	}
	
	/**
	 * Dump the classAttrs and classesPairs to outFile
	 * 
	 * @param outFile, the output file
	 * @param binaryOutput, output in binary or not
	 */
	public void dumpSummaryToFile(File outFile, AllClassesSummary summary, boolean binaryOutput) {
		System.out.println("Dumping output to file: " + outFile);
		try {
			ProtoBufferUtil.saveMessage(summary, outFile, binaryOutput);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}
