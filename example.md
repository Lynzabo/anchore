```shell
[root@localhost anchore]# anchore --help
Usage: anchore [OPTIONS] COMMAND [ARGS]...

  Anchore is a tool to analyze, query, and curate container images. The
  options at this top level control stdout and stderr verbosity and format.

  After installation, the first command run should be: 'anchore feeds list'
  to initialize the system and load feed data.

  High-level example flows:

  Initialize the system and sync the by-default subscribed feed
  'vulnerabilties':

  anchore feeds list
  anchore feeds sync

  Analyze an image

  docker pull nginx:latest anchore analyze --image nginx:latest --imagetype
  base

  Generate a summary report on all analyzed images

  anchore audit report

  Check gate output for nginx:latest:

  anchore gate --image nginx:latest

Options:
  --verbose                       Enable verbose output to stderr.
  --debug                         Developer debug output to stderr.
  --quiet                         Only errors to stderr, no status messages.
  --json                          Output formatted json to stdout.
  --plain                         Output formatted scriptable text to stdout.
  --html                          Output formatted HTML table to stdout.
  --config-override <config_opt>=<config_value>
                                  Override an anchore configuration option
                                  (can be used multiple times).
  --version                       Show the version and exit.
  --extended-help                 Show extended help content, similar to
                                  manpage, and exit.
  --help                          Show this message and exit.

Commands:
  analyze       Perform analysis on specified image IDs.
  audit         Commands to generate/review audit reports
  feeds         Manage syncing of and subscriptions to Anchore data feeds.
  gate          Perform and view gate evaluation on selected images
  login         Log in to the Anchore service.
  logout        Log out of the Anchore service.
  policybundle  Manage syncing your stored policy bundles.
  query         Run specified query (leave blank to show list).
  system        System level operations.
  toolbox       Useful tools and operations on images and containers
  whoami        Show user data for current logged-in user if available
[root@localhost anchore]# 

[root@localhost anchore]# 查看同步信息,包括漏洞和包信息
[root@localhost anchore]# anchore feeds list
Subscribed:
  vulnerabilities:
    description: This feed provides vulnerability data for various linux distributions
      in json form
Unavailable/Insufficient Access Tier:
  packages:
    description: This feed provides package data for various application package systems
      in json form
[root@localhost anchore]# 请求去同步漏洞和包信息
[root@localhost anchore]# anchore feeds sync
syncing data for subscribed feed (vulnerabilities) ...
	syncing group data: debian:unstable: ...
	syncing group data: ubuntu:16.04: ...
	syncing group data: centos:6: ...
	syncing group data: centos:7: ...
	syncing group data: centos:5: ...
	syncing group data: ubuntu:14.10: ...
	syncing group data: ubuntu:15.04: ...
	syncing group data: debian:9: ...
	syncing group data: debian:8: ...
	syncing group data: ubuntu:12.04: ...
	syncing group data: debian:7: ...
	syncing group data: ubuntu:16.10: ...
	syncing group data: alpine:3.3: ...
	syncing group data: alpine:3.4: ...
	syncing group data: alpine:3.5: ...
	syncing group data: alpine:3.6: ...
	syncing group data: ol:6: ...
	syncing group data: ubuntu:14.04: ...
	syncing group data: ubuntu:15.10: ...
	syncing group data: ubuntu:12.10: ...
	syncing group data: ubuntu:17.04: ...
	syncing group data: ol:7: ...
	syncing group data: ubuntu:13.04: ...
	syncing group data: ol:5: ...
skipping data sync for unsubscribed feed (packages) ...
[root@localhost anchore]# 请求解析镜像
[root@localhost anchore]# anchore analyze --image nginx:latest --imagetype base

[root@localhost anchore]# 获取镜像的解析结果，包括包信息，文件，漏洞信息等。
[root@localhost anchore]# anchore audit --image nginx:latest report
+--------------+------+--------------+--------------+-------------+-------------+---------------------+------------+
| Image Id     | Type | Current Tags | All Tags     | Gate Status | Size(bytes) | Counts              | Base Diffs |
+--------------+------+--------------+--------------+-------------+-------------+---------------------+------------+
| da5939581ac8 | base | nginx:latest | nginx:latest | UNKNOWN     | 108271609   | PKGS=108 FILES=5274 | N/A        |
|              |      |              |              |             |             | SUIDFILES=8         |            |
+--------------+------+--------------+--------------+-------------+-------------+---------------------+------------+

[root@localhost anchore]# 查看镜像中是否包含包zzz，aaa
[root@localhost anchore]# anchore query --image nginx:latest has-package curl wget
+----------+----------+-------------+---------+---------+
| Image Id | Repo Tag | Query Param | Package | Version |
+----------+----------+-------------+---------+---------+
+----------+----------+-------------+---------+---------+

[root@localhost anchore]# 查看包中包含所有文件信息
[root@localhost anchore]# anchore query --image nginx:latest list-files-detail all
+--------------+--------------+---------------------------+-------+----------+-------+---------------------------+---------------------------+
| Image Id     | Repo Tags    | Filename                  | Type  | Size     | Mode  | Link Dest                 | Checksum                  |
+--------------+--------------+---------------------------+-------+----------+-------+---------------------------+---------------------------+
| da5939581ac8 | nginx:latest | /usr/lib/x86_64-linux-gnu | file  | 4802     | 0644  | N/A                       | a82015a87e5674584856f531e |
|              |              | /perl-base/unicore/lib/In |       |          |       |                           | 4143deeb2ede5c72b9b106f08 |
|              |              | /3_1.pl                   |       |          |       |                           | fd72ce6159a39b            |
| da5939581ac8 | nginx:latest | /usr/share/zoneinfo/right | slink | 9        | 0777  | ../Poland                 | DIRECTORY_OR_OTHER        |
|              |              | /Europe/Warsaw            |       |          |       |                           |                           |
| da5939581ac8 | nginx:latest | /var/lib/dpkg/info/libude | file  | 60       | 0644  | N/A                       | f2bec0f57ef529571abb4370d |
|              |              | v1:amd64.triggers         |       |          |       |                           | 4e3cfa911ae3606a0d31559bc |
|              |              |                           |       |          |       |                           | a5980c0a1de91e            |
| da5939581ac8 | nginx:latest | /usr/share/doc/libpam-    | dir   | 22       | 0755  | N/A                       | DIRECTORY_OR_OTHER        |
|              |              | modules                   |       |          |       |                           |                           |
| da5939581ac8 | nginx:latest | /usr/share/zoneinfo/right | slink | 4        | 0777  | Guam                      | DIRECTORY_OR_OTHER        |
|              |              | /Pacific/Saipan           |       |          |       |                           |                           |
| da5939581ac8 | nginx:latest | /usr/bin/sha224sum        | file  | 56168    | 0755  | N/A                       | bf49bc5ae0f5057a1a7d6568f |
|              |              |                           |       |          |       |                           | 34573015185c2b127ff466e53 |
|              |              |                           |       |          |       |                           | 14a1a97f396164            |
| da5939581ac8 | nginx:latest | /usr/lib/gcc              | dir   | 29       | 0755  | N/A                       | DIRECTORY_OR_OTHER        |

| da5939581ac8 | nginx:latest | /usr/share/zoneinfo/posix | slink | 24       | 0777  | ../../Australia/Adelaide  | DIRECTORY_OR_OTHER        |
|              |              | /Australia/Adelaide       |       |          |       |                           |                           |
| da5939581ac8 | nginx:latest | /usr/lib/x86_64-linux-gnu | file  | 838      | 0644  | N/A                       | f442e3c03c2e5bf4e4cff85fe |
|              |              | /perl-base/unicore/lib/Sc |       |          |       |                           | a65895e3dd30b3a8d8897ccf5 |
|              |              | /Ethi.pl                  |       |          |       |                           | 876d543721357b            |
| da5939581ac8 | nginx:latest | /usr/share/zoneinfo/Syste | slink | 22       | 0777  | ../America/Puerto_Rico    | DIRECTORY_OR_OTHER        |
|              |              | mV/AST4                   |       |          |       |                           |                           |
| da5939581ac8 | nginx:latest | /var/lib/dpkg/info/e2fspr | file  | 17       | 0644  | N/A                       | 4a21d18e62ee18b0b1afd9436 |
|              |              | ogs.conffiles             |       |          |       |                           | 4e581e0b9b9881ea6e2df831f |
|              |              |                           |       |          |       |                           | e8d4086a9672b9            |
+--------------+--------------+---------------------------+-------+----------+-------+---------------------------+---------------------------+

[root@localhost anchore]# 查看包所有CVE
[root@localhost anchore]# anchore query --image nginx:latest cve-scan all
+------------------+------------+-----------------+---------------------------+-----------------+---------------------------+----------------+---------------------------+
| CVE ID           | Severity   | *Total Affected | Vulnerable Package        | Fix Available   | Fix Images                | Rebuild Images | URL                       |
+------------------+------------+-----------------+---------------------------+-----------------+---------------------------+----------------+---------------------------+
| CVE-2017-9937    | Negligible | 1               | libjbig0-2.1-3.1+b2       | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-9937                   |
| CVE-2017-9935    | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-9935                   |
| CVE-2017-9614    | Medium     | 1               | libjpeg62-turbo-1:1.5.1-2 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-9614                   |
| CVE-2017-9117    | Negligible | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-9117                   |
| CVE-2017-8872    | Medium     | 1               | libxml2-2.9.4+dfsg1-2.2+d | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | eb9u1                     |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-8872                   |
| CVE-2017-8804    | High       | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-8804                   |
| CVE-2017-8804    | High       | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-8804                   |
| CVE-2017-8804    | High       | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-8804                   |
| CVE-2017-7246    | Negligible | 1               | libpcre3-2:8.39-3         | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-7246                   |
| CVE-2017-7245    | Negligible | 1               | libpcre3-2:8.39-3         | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-7245                   |
| CVE-2017-5969    | Low        | 1               | libxml2-2.9.4+dfsg1-2.2+d | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | eb9u1                     |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-5969                   |
| CVE-2017-5563    | Negligible | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-5563                   |
| CVE-2017-3735    | Medium     | 1               | libssl1.1-1.1.0f-3        | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-3735                   |
| CVE-2017-13734   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13734                  |
| CVE-2017-13734   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13734                  |
| CVE-2017-13734   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13734                  |
| CVE-2017-13734   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13734                  |
| CVE-2017-13734   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13734                  |
| CVE-2017-13733   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13733                  |
| CVE-2017-13733   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13733                  |
| CVE-2017-13733   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13733                  |
| CVE-2017-13733   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13733                  |
| CVE-2017-13733   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13733                  |
| CVE-2017-13732   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13732                  |
| CVE-2017-13732   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13732                  |
| CVE-2017-13732   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13732                  |
| CVE-2017-13732   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13732                  |
| CVE-2017-13732   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13732                  |
| CVE-2017-13731   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13731                  |
| CVE-2017-13731   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13731                  |
| CVE-2017-13731   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13731                  |
| CVE-2017-13731   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13731                  |
| CVE-2017-13731   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13731                  |
| CVE-2017-13730   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13730                  |
| CVE-2017-13730   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13730                  |
| CVE-2017-13730   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
| CVE-2017-13728   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13728                  |
| CVE-2017-13728   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13728                  |
| CVE-2017-13728   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13728                  |
| CVE-2017-13728   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13728                  |
| CVE-2017-13727   | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13727                  |
| CVE-2017-13726   | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-13726                  |
| CVE-2017-12944   | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12944                  |
| CVE-2017-12883   | Medium     | 1               | perl-base-5.24.1-3+deb9u1 | 5.24.1-3+deb9u2 | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12883                  |
| CVE-2017-12837   | Negligible | 1               | perl-base-5.24.1-3+deb9u1 | 5.24.1-3+deb9u2 | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12837                  |
| CVE-2017-12424   | High       | 1               | passwd-1:4.4-4.1          | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12424                  |
| CVE-2017-12424   | High       | 1               | login-1:4.4-4.1           | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12424                  |
| CVE-2017-12133   | Medium     | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12133                  |
| CVE-2017-12133   | Medium     | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12133                  |
| CVE-2017-12133   | Medium     | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12133                  |
| CVE-2017-12132   | Medium     | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12132                  |
| CVE-2017-12132   | Medium     | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12132                  |
| CVE-2017-12132   | Medium     | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-12132                  |
| CVE-2017-11613   | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11613                  |
| CVE-2017-11335   | Medium     | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11335                  |
| CVE-2017-11164   | Negligible | 1               | libpcre3-2:8.39-3         | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11164                  |
| CVE-2017-11113   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11113                  |
| CVE-2017-11113   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11113                  |
| CVE-2017-11113   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11113                  |
| CVE-2017-11113   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11113                  |
| CVE-2017-11113   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11113                  |
| CVE-2017-11112   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11112                  |
| CVE-2017-11112   | Medium     | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11112                  |
| CVE-2017-11112   | Medium     | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11112                  |
| CVE-2017-11112   | Medium     | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11112                  |
| CVE-2017-11112   | Medium     | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-11112                  |
| CVE-2017-10685   | High       | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10685                  |
| CVE-2017-10685   | High       | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10685                  |
| CVE-2017-10685   | High       | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10685                  |
| CVE-2017-10685   | High       | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10685                  |
| CVE-2017-10685   | High       | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10685                  |
| CVE-2017-10684   | High       | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | bin-6.0+20161126-1        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10684                  |
| CVE-2017-10684   | High       | 1               | ncurses-                  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | base-6.0+20161126-1       |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10684                  |
| CVE-2017-10684   | High       | 1               | libtinfo5-6.0+20161126-1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10684                  |
| CVE-2017-10684   | High       | 1               | libncursesw5-6.0+20161126 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | -1                        |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10684                  |
| CVE-2017-10684   | High       | 1               | libncurses5-6.0+20161126- | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | 1                         |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10684                  |
| CVE-2017-10140   | Unknown    | 1               | libdb5.3-5.3.28-12+b1     | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-10140                  |
| CVE-2017-1000082 | Negligible | 1               | libudev1-232-25+deb9u1    | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-1000082                |
| CVE-2017-1000082 | Negligible | 1               | libsystemd0-232-25+deb9u1 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 17-1000082                |
| CVE-2016-9318    | Medium     | 1               | libxml2-2.9.4+dfsg1-2.2+d | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | eb9u1                     |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 16-9318                   |
| CVE-2016-9085    | Negligible | 1               | libwebp6-0.5.2-1          | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 16-9085                   |
| CVE-2016-2781    | Low        | 1               | coreutils-8.26-3          | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 16-2781                   |
| CVE-2016-2779    | High       | 1               | util-linux-2.29.2-1       | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 16-2779                   |
| CVE-2016-2779    | High       | 1               | mount-2.29.2-1            | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
| CVE-2015-8985    | Negligible | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 15-8985                   |
| CVE-2015-8985    | Negligible | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 15-8985                   |
| CVE-2014-8130    | Negligible | 1               | libtiff5-4.0.8-2+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 14-8130                   |
| CVE-2013-4392    | Negligible | 1               | libudev1-232-25+deb9u1    | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-4392                   |
| CVE-2013-4392    | Negligible | 1               | libsystemd0-232-25+deb9u1 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-4392                   |
| CVE-2013-4235    | Negligible | 1               | passwd-1:4.4-4.1          | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-4235                   |
| CVE-2013-4235    | Negligible | 1               | login-1:4.4-4.1           | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-4235                   |
| CVE-2013-0340    | Negligible | 1               | libexpat1-2.2.0-2+deb9u1  | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-0340                   |
| CVE-2013-0337    | Low        | 1               | nginx-1.13.5-1~stretch    | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 13-0337                   |
| CVE-2012-3878    | Negligible | 1               | perl-base-5.24.1-3+deb9u1 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 12-3878                   |
| CVE-2011-4116    | Negligible | 1               | perl-base-5.24.1-3+deb9u1 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 11-4116                   |
| CVE-2011-3374    | Negligible | 1               | libapt-pkg5.0-1.4.7       | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 11-3374                   |
| CVE-2011-3374    | Negligible | 1               | apt-1.4.7                 | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 11-3374                   |
| CVE-2010-4756    | Negligible | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4756                   |
| CVE-2010-4756    | Negligible | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4756                   |
| CVE-2010-4756    | Negligible | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4756                   |
| CVE-2010-4052    | Negligible | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4052                   |
| CVE-2010-4052    | Negligible | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4052                   |
| CVE-2010-4052    | Negligible | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4052                   |
| CVE-2010-4051    | Negligible | 1               | multiarch-                | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 | support-2.24-11+deb9u1    |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4051                   |
| CVE-2010-4051    | Negligible | 1               | libc6-2.24-11+deb9u1      | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4051                   |
| CVE-2010-4051    | Negligible | 1               | libc-bin-2.24-11+deb9u1   | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-4051                   |
| CVE-2010-0928    | Negligible | 1               | libssl1.1-1.1.0f-3        | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 10-0928                   |
| CVE-2009-4487    | Negligible | 1               | nginx-1.13.5-1~stretch    | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 09-4487                   |
| CVE-2007-6755    | Negligible | 1               | libssl1.1-1.1.0f-3        | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 07-6755                   |
| CVE-2007-5686    | Negligible | 1               | passwd-1:4.4-4.1          | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 07-5686                   |
| CVE-2007-5686    | Negligible | 1               | login-1:4.4-4.1           | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 07-5686                   |
| CVE-2005-2541    | Negligible | 1               | tar-1.29b-1.1             | None            | da5939581ac8(nginx:latest | None           | https://security-tracker. |
|                  |            |                 |                           |                 | )                         |                | debian.org/tracker/CVE-20 |
|                  |            |                 |                           |                 |                           |                | 05-2541                   |
+------------------+------------+-----------------+---------------------------+-----------------+---------------------------+----------------+---------------------------+

[root@localhost anchore]# anchore toolbox --image nginx:latest show
IMAGEID='da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675'
REPOTAGS='nginx:latest'
DISTRO='debian'
DISTROVERS='9'
HUMANNAME='nginx:latest'
SHORTID='da5939581ac8'
PARENTID=''
BASEID='da5939581ac835614e3cf6c765e7489e6d0fc602a44e98c07013f1c938f49675'
IMAGETYPE='base'
[root@localhost anchore]# 
[root@localhost anchore]# 
```
