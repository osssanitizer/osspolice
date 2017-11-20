# HOWTO #
To run class-signature.jar:
```
java -jar class-signature.jar -apk /data/Desktop/app-signature/analyzer/../data/own-app/hideicon.play.v2.apk -outDir /data/Desktop/app-signature/analyzer/../data/CRG-results/ -androidJarDir /home/ruian/Android/Sdk/platforms -suppressOutput
```

# NOTE #
1. Python call Java, [summary link](http://baojie.org/blog/2014/06/16/call-java-from-python/)
Jpype works pretty well, but Pyjnius is faster and simpler than JPype

2. Or use subprocess directly, the simple way

3. Various ways to communicate with Python [link](https://wiki.python.org/moin/IntegratingPythonWithOtherLanguages)

4. *TODO*: By default soot runs the analysis program by initiating num of threads equal to available processors. We want to make this as an option.

- [This is the implementation file](soot/src/soot/PackManager.java)

- It uses *Runtime.getRuntime().availableProcessors()* to get number of logical processors, and we want to limit this

- It uses *CountingThreadPoolExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue)*[link](http://download.eclipse.org/eclipsescada/javadoc/0.2/org/eclipse/scada/utils/concurrent/CountingThreadPoolExecutor.html) to get initiate the thread pool.

# TODO #
1. Feature: Process apps/jars that have missing dependencies, I guess. This may be problematic in some cases, but we need to know there are how many of them.
giphy4j-1.0.1.jar, processing errors, because of error in the jb phase, missing dependencies

2. LGPL in Android apps is tricky, and license change is tricky as well.
[pretty time has changed from LGPL to ASL](https://github.com/ocpsoft/prettytime/issues/29)

3. Add process-count parameter to the code

4. Add process-based implementation
