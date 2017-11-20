# Differences between native indexing and java indexing #
1. Leaf node is not file, so I used a separate set to maintain the leaf nodes

2. String matches and functions matches should be maintained separately, because I need to check whether the developer is violating LGPL, i.e. strings match, but functions doesn't.

3. In addition to repo id mapping to repo_id, I also added repo id mapping to software id and version information. Maybe this can be improved.

# Note 2016 Oct 10 #
1. This line ay not be reliable, because there is possibility that the key will be less than 30. I changed this to depend on feature_type.
``
if len(str(key)) > 30: # XXX Hack (only files will have this)
```

2. This function, the count (return value) should be sum of v or number of keys? I am using sum of v. But you are using number of keys.
```
build_repo_indexing_features
``` 

# NOTE 2016 Oct 15 #
In Java, we added key type prefix to each key. The number of keys have the following attributes because of our design.
1. each file has a reverse mapping, this is guarateed by test_and_set.
len(files-xxx) == len(r-files-xxx)

2. not all dirs have a upwards mapping, because although there are files mapping to it, some directories without those minor files may have been already indexed, so when going upwards,
current dirs-xxx are not used, but the similar node's dirs-xxx are used, and thus current node doesn't have a upwards mapping.
len(dirs-xxx) < len(r-dirs-xxx)

3. the number of repo-xxx should be consistent with total-repos

# NOTE 2016 Nov 23 #
If we are migrating the postgresql database, we need to migrate the database,
as well as do the following things
 
1. modify the configurations (/etc/postgresql/9.5/main/postgresql.conf)
to allow to any incoming address and increase the maximum connections.
```
listen_addresses = '*'                                             
port = 5432             # (change requires restart)                
max_connections = 1000         # (change requires restart)        
```

2. modify the configurations (/etc/postgresql/9.5/main/pg_hba.conf)
to allow any incoming address and incease the maximum connections.
```
host        all     all     0.0.0.0/0          trust
```

# NOTE 2016 Dec 20 #
1. Before adding version database, the size for indexing 56 repos are
(157000L, [157000L])
(87848784, [87848784])
56
2. After adding version database, the size for indexing 56 repos are (the size almost doubled!)
(270134L, [270134L])
(131615968, [131615968])
56
3. After adding version database and using software-, softwareversion- prefix, the size for indexing 56 repos are (size is close)
(270143L, [270143L])
(131641312, [131641312])
56
4. After applying static final string patch, the size for indexing 56 repos are
(260615L, [260615L])
(122635488, [122635488])
56
5. After adding class-level reverse mapping, for co-location testing, the size for indexing 56 repos are
(391249L, [391249L])
(194927344, [194927344])
56
6. After optimization by avoiding setting duplicate keys for features that matches more than two versions, the size for indexing 56 repos are
(391187L, [391187L])
(188926224, [188926224])
56
7. After removing functions from versions database! The size for indexing 56 repos are
(194227L, [194227L])
(105903936, [105903936])
56
8. Testing centroids now!
if using sorted set, the number of identified centroids are:
# 0.6, 0.01 -. 986
# 0.6, 0.02 -, 1212
# 0.6, 0.04 -, 2035

- only_one_bin is False,
    ```
    (78896L, [78896L])
    (22133456, [22133456])
    18
    ```
- only_one_bin is False, this one can match mopub, when score is set to 0.5.
    ```
    (598530L, [598530L])
    (173468800, [173468800])
    45
    ```
- only_one_bin is True,
    ```
    (16945L, [16945L])
    (9959008, [9959008])
    18
    ```
- only_one_bin is True, but this one match mopub when score is set to 0.5.
    ```
    (196087L, [196087L])
    (94625600, [94625600])
    45
    ```
- only_one_bin is True, MDD = 0.02, when score is set to 0.5.
    ```
    (196109L, [196109L])
    (95558288, [95558288])
    45
    ```

- only_one_bin is True, MDD = 0.05, when score is set to 0.5.
    ```
    (194479L, [194479L])
    (93551664, [93551664])
    45
    ```
- USE_CENTROID_BIN is False, i.e. use zset to store centroids.
For indexing mopub, the unique centroids are 900 ~ 1200 level
For searching mopub, the aar yields 900~1200 centroids to search
For searching mopub, the com.alawar.MountainCrimeRequital-1024.apk yields 6000~7000 centroids to search
    ```
    (198432L, [198432L])
    (111443440, [111443440])
    56
    ```
- USE_CENTROID_BIN is True, i.e. use hset bins to store centroids.
For searching mopub, the mopub-4.4.0 matched 1144 centroids
    After fixing the lower threshold, the mopub-4.4.0 matched 1212 centroids
    After fixing the lower threshold
    - For searching mopub, the com.alawar.MountainCrimeRequital-1024.apk yields 1500 centroids to search
    - For searching mopub, if we remove the upper threshold the com.alawar.MountainCrimeRequital-1024.apk yields 1341 centroids to search

    ```
    (205228L, [205228L])
    (103276240, [103276240])
    56
    ```
- After setting the threshold of MDD to 0.02
    - mopub-4.4.0 matched 1418 centroids, costs 1.6 seconds
    - mopub-4.1.0 matched 1421 centroids, costs 1.5 seconds
    - the com.alawar.MountainCrimeRequital-1024.apk yields 2522 centroids to search, and cost 44 seconds, and only works at TFIDF = 0.5
    - after setting add the upper threshold to the search scope, the com.alawar.MountainCrimeRequital-1024.apk yields 2886 centroids to search, and cost 86 seconds, 
    ```
    (204993L, [204993L])
    (103306816, [103306816])
    56
    ```
- USE_CENTROID_BIN is False, i.e. use zset to store centroids.
    - mopub-4.4.0 matched 986 centroids, cost 1.97 seconds
    - mopub-4.1.0 matched 975 centroids, cost 1.84 seconds
    - com.alawar.MountainCrimeRequital-1024.apk matched 6890 centroids, cost 23 seconds
    ```
    (198438L, [198438L])
    (111402496, [111402496])
    56
    ```
##########################################################################################################
## Selecting this setting, because I think the performance is within control now!
##########################################################################################################
- USE_CENTROID_BIN is False, i.e., use zset to store centroids, but optimize the version db.
    ```
    (192484L, [192484L])
    (105042560, [105042560])
    57
    ```

# Note Jan 7 #
clone a repo with depth 1 and specific tag
```
git clone --branch OpenSSL_1_0_1h --depth=1 https://github.com/openssl/openssl.git
```
