1. `anchore analyze --image nginx:latest --imagetype base`日志输出
```shell
[root@localhost ~]# anchore analyze --image nginx:latest --imagetype base
Analyzing image: nginx:latest
da5939581ac8: analyzing ...
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/01_analyzer_meta.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpl4jkBy /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 3.39093589783
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/02_layers.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpEFJ7Lf /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.700896024704
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/10_package_list.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpL3usNI /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.708620786667
analyzer status: success
analyzer exitcode: 0
analyzer output: analyzer starting up: imageId=da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 meta={'DISTROVERS': u'9', 'LIKEDISTRO': u'debian', 'DISTRO': u'debian'} distrodict={'fullversion': u'9', 'version': u'9', 'likeversion': u'9', 'likedistro': u'debian', 'flavor': 'DEB', 'distro': u'debian'}

running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/11_package_detail_list.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpR1YExH /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.663886070251
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/12_gem_package_list.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpX9KTWp /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.906648874283
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/12_npm_package_list.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpPwkuCc /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.718153953552
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/13_content_search.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmp73qgey /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.648241996765
analyzer status: success
analyzer exitcode: 0
analyzer output: No regexp configuration found in analyzer_config.yaml for analyzer 'content_search, skipping

running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/13_retrieve_files.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpE6GwRW /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 0.632249116898
analyzer status: success
analyzer exitcode: 0
analyzer output: No configuration found in analyzer_config.yaml for analyzer 'retrieve_files, skipping

running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/20_file_list.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpE_jUGw /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 1.09965085983
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/30_file_checksums.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmpp98TI9 /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 14.2429811954
analyzer status: success
analyzer exitcode: 0
analyzer output:
running analyzer: /root/.local/lib/python2.7/site-packages/anchore/anchore-modules/analyzers/40_file_suids.py da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675 /root/.anchore/data /root/.anchore/anchoretmp/1068362.anchoretmp/tmp8eaG_p /root/.anchore/anchoretmp/1068362.anchoretmp
analyzer time (seconds): 1.66484880447
analyzer status: success
analyzer exitcode: 0
analyzer output:
da5939581ac8: analyzed.
[root@localhost ~]#
```