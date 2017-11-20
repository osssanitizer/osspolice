# HOWTO #
1. index repos
    - cmd is ```python detector.py index /data/gpl_violation/data/repos/```

2. search native libs
    - cmd is ```python detector.py search /data/gpl_violation/data/apks/```

3. index java
    - cmd is ```python detector.py java_index /data/gpl_violation/data/maven/ jar```

4. search java
    - cmd is ```python detector.py java_search /data/gpl_violation/data/apks-sack1-extract/ dex```

5. signature java
    - cmd is ```python detector.py java_signature /data/gpl_violation/data/apks-sack1-extract/ dex```

6. Netdata Indexing Plugin
To enable plugin:
    $ sudo cp gpl.plugin.py /usr/libexec/netdata/plugins.d/gpl.plugin
    $ sudo chmod +x /usr/libexec/netdata/plugins.d/gpl.plugin
    $ sudo killall netdata
    $ sudo netdata
