# TB337FC / TB330FU Carbonara 与 Bootloader 解锁研究记录

> 更新时间：2026-09-11
>
> 本文记录一台自有的联想教育定制版 TB337FC。设备在 fastboot 中显示为
> `TB330FU`，因此文中的平台匹配、地址和补丁只对这台设备及相同固件版本
> 具有参考价值。不要把它们直接套到其他 MTK 设备。

## 结论先行

目前已经完成了三件关键事情：

1. Windows + WinUSB 可以稳定与 Preloader 通信并读取 GPT、分区和 `super`。
2. 官方 DA 被 `carbonara_checker.py` 判定为 DA1 未修补，Carbonara 可以成功运行。
3. DA2 的 Lenovo 存储写入门槛可以在内存中补丁绕过；随后直接修改 `seccfg` V4 成功，
   `fastboot getvar unlocked` 返回 `unlocked: yes`。

因此，这台设备现在已经处于实际的 bootloader unlocked 状态，可以继续进行 boot、AVB、
系统和 Lenovo OEM 定制研究。

仓库只包含明确选定的设备匹配 DA 样本，位于 `vendor/TB330FU/`。不包含 auth 文件、
分区备份、设备唯一 ID 或本机日志。请保持仓库为 private，并在本机自行提供匹配的
认证文件。

## 设备与 USB 状态

- 商业型号：TB337FC（教育/OEM 定制版）
- fastboot 型号：TB330FU
- SoC：MT6768/MT6769，Preloader HW code `0x707`
- HW subcode：`0x8A00`
- HW version：`0xCA00`
- Preloader：VID `0x0E8D` / PID `0x2000`
- 期望的 BootROM 枚举通常是 VID `0x0E8D` / PID `0x0003`，本机没有通过软件方法稳定得到
- Preloader 插入 USB 后只持续约 1 秒，因此程序必须先启动，再立即插线

MEID、SOCID、序列号、备份路径、网络地址和认证材料均不写入本仓库。

### Windows 传输经验

- WinUSB 是本机目前最可靠的后端，Zadig 中应给 `MediaTek Preloader` 安装 WinUSB。
- UsbDk 在本机曾出现握手超时、I/O error 和 CDC endpoint 对象不匹配。
- CDC VCOM 虽然可以工作，但读写速度只有约 3--5 MB/s；WinUSB 曾达到约 15--17 MB/s。
- 不要把 COM 端口名硬编码进流程；本机端口号会变化。

PowerShell 中可以使用：

```powershell
$env:MTKCLIENT_USB_BACKEND = 'winusb'
$env:MTKCLIENT_CONSOLE_LOGLEVEL = 'INFO'
$env:MTKCLIENT_TRACE_IO = '0'
```

## 已尝试的进入 BootROM 方法

| 方法 | 结果 | 结论 |
|---|---|---|
| 音量键/电源键组合 | 失败 | 这台平板没有通过按键稳定进入 BootROM |
| 经典 `crashda` | 失败，返回 `0x1D18` | 不是 RSA 失败，而是 DA 参数先过不了长度 gate |
| 官方 Flash Tool | 无法作为起点使用 | 官方流程假设设备已经在 BootROM |
| DA `forcebrom` / `usbdl_flag` | 失败 | MMIO 写入和读回成功，但复位后仍回到 PID `0x2000` |
| DA watchdog / 软件复位 | 只能让 USB 重新枚举 | 复位后 Preloader 再次运行，BootROM 没有采纳 flag |
| Meta 菜单 | 可以进入菜单 | 尚未证明 Meta 能提供刷写或解锁路径 |
| 拆机测试点 | 未尝试 | 仅作为最后的硬件恢复手段 |
| Carbonara | 成功 | 当前实际可用的入口是 Preloader -> Carbonara -> DA |

### `0x1D18` 的准确含义

Preloader Phase 7 中观察到：

```asm
0x3F20: CMP    R7, FP
0x3F22: BHI    0x3F3A
0x3F2E: MOVW   FP, #0x1D18
```

经典 crashmode 0 发出的参数为：

```text
DA_size = 0x100
sig_len = 0x100
```

所以 `size <= sig_len`，直接进入 `0x1D18`。这发生在真正的证书/RSA 验证之前，不能
据此断言签名不匹配。

## Carbonara 成功链路

官方 DA 文件被检查为：

```text
DA1 未修补：True
```

运行时可以看到：

```text
Exploitation - DA is vulnerable to Carbonara :)
Mtk - Patched "Patched loader msg" in preloader
Mtk - Patched "get_vfy_policy" in preloader
XFlashExt - Security check patched
XFlashExt - DA version anti-rollback patched
XFlashExt - SBC patched to be disabled
XFlashExt - Register read/write not allowed patched
Exploitation - Carbonara got served! Enjoy your meal ;)
```

这些补丁只存在于本次运行时内存，不等于把补丁写入了设备的 Preloader 或 DA 分区。

### Lenovo DA 存储写入 gate

从匹配设备的 DA2 中确认了 `allow_download` gate：

- DA2 文件偏移：`0x3EF64`
- DA2 加载基址：`0x40000000`
- 对应运行时地址：`0x4003EF64`
- 原始字节：`01 4B 18 68 70 47 00 BF`
- 运行时替换：`01 20 70 47 00 BF 00 BF`
- 效果：让 gate 返回 `1`

补丁代码采用了 fail-closed 检查：只有 DA2 基址正确且原始字节完全匹配时才修改；
否则拒绝继续。补丁仅在 DA2 内存中生效，不写回闪存。

成功日志示例：

```text
EXPERIMENTAL: DA storage-write gate patched in memory
DA write patch bytes: 01 4b 18 68 70 47 00 bf -> 01 20 70 47 00 bf 00 bf
```

### 关于 AllInOne DA

官方 `MTK_AllInOne_DA-resign.bin` 大于 Phase 7 观察到的单次 `0x40000` 限制，因此不能
简单把整个文件当成一次 SEND_DA 载荷。它更像是包含多个目标/阶段的容器，Flash Tool
会先解析并选择 MT6768 对应的 stage，再上传给 Preloader。

## Bootloader 解锁

### 实际采用的方法

没有使用 fastboot 的 `oem unlock`，而是：

1. 通过 Carbonara 进入可用 DA。
2. 在 DA2 内存中打开 Lenovo storage-write gate。
3. 读取并识别 `seccfg` 为 V4。
4. 使用设备硬件加密流程生成 V4 的 unlock 配置。
5. 把生成的配置写回 `seccfg`。
6. 进入 fastboot 验证。

验证结果：

```text
fastboot getvar unlocked
unlocked: yes
```

这证明 LK/fastboot 读取到的有效锁状态已经是 unlocked。

### 当前 fork 的解锁命令

先准备匹配固件中的以下文件（DA 也可以直接使用仓库内的样本）：

- `MTK_AllInOne_DA-resign.bin`
- `image\preloader_barley_row_wifi.bin`
- `auth_sv5.auth`

仓库内 DA 样本：`vendor/TB330FU/MTK_AllInOne_DA-resign.bin`。

然后在 PowerShell 手动执行：

```powershell
$Repo = 'D:\path\to\mtkclient-carbonara'
$FW = 'D:\path\to\TB330FU_ROW_OPEN_USER_V5_V_ZUI_17.0.074_ST_250417'
$DA = Join-Path $Repo 'vendor\TB330FU\MTK_AllInOne_DA-resign.bin'

$env:MTKCLIENT_USB_BACKEND = 'winusb'
$env:MTKCLIENT_CONSOLE_LOGLEVEL = 'INFO'
$env:MTKCLIENT_TRACE_IO = '0'
Set-Location $Repo

python.exe .\mtk.py da seccfg unlock `
  --ptype carbonara `
  --experimental-da-write `
  --loader "$DA" `
  --preloader "$FW\image\preloader_barley_row_wifi.bin" `
  --auth "$FW\auth_sv5.auth" `
  --vid 0x0e8d `
  --pid 0x2000
```

应看到 `Detected V4 Lockstate`，随后写入进度完成。成功后可以用：

```powershell
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar slot-count
```

### 数据清除说明

这次没有观察到 userdata 被清空。原因很可能是直接写入 `seccfg`，没有调用 Android
fastboot 官方解锁流程中的 wipe callback；这不代表以后所有版本都会保留数据。解锁前仍
应备份需要的数据，因为首次启动可能触发加密/校验逻辑或恢复出厂。

`seccfg` 解锁也不等于自动移除 Lenovo 的所有教育管控、`lenovolock` 内容或 AVB 策略；
这些属于不同层次。

## 分区备份策略

### 第一优先级：设备唯一数据

```text
nvram nvdata nvcfg persist protect1 protect2 proinfo
sec1 seccfg otp flashinfo
```

### 第二优先级：OEM/启动状态

```text
lenovolock lenovosku_1 lenovosku_2 misc para metadata
boot_para frp
```

### 第三优先级：启动链和系统

```text
vbmeta* lk_a lk_b boot_a boot_b vendor_boot_a vendor_boot_b
init_boot_a init_boot_b dtbo_a dtbo_b tee_a tee_b
spmfw* scp* sspm* gz* md1img* logo lenovoraw lenovocust super
```

`super` 约 11 GiB，值得备份；`userdata` 约 103 GiB，可以最后处理。不要把上述备份
放进本仓库。

## Logo 实验结果

曾将自制的 8 MiB `logo` 镜像写入 GPT 中的 `logo` 分区，日志显示完整写入成功；设备随后
无法正常开机。用写入前的原始 `logo` 备份恢复后，设备重新开机。

这证明了 DA 写入路径是真实有效的，也证明了恢复路径可用。当前不能把原因简单归结为
“文件太大”：自制文件和分区都是 8 MiB，MTK header 和 slot 数也存在。更可能是第一
个 1200x1920 图像的像素/压缩/透明度或整个 logo 容器的细节不完全符合该版本 LK 的
读取预期，具体原因仍需离线对比和逐步实验。

经验：第一次改 logo 应保留原容器中的所有 slot，只替换一个已确认尺寸和色彩布局的
图像；每次改动前都保存原始分区和改后读回校验。

## 下一步建议

1. 重新读取并保存当前 `seccfg`、GPT 和关键分区，记录解锁后的基线哈希。
2. 用 `fastboot getvar current-slot` 确认当前槽位，A/B 分区始终成对备份。
3. 先从 `boot`/`vbmeta` 的离线解析开始，再尝试最小改动；不要一开始写 `preloader`、
   `lk`、`tee`、`otp` 或 `rpmb`。
4. 研究 AVB、rollback index 和 Lenovo `lenovolock` 是三个独立问题，不要混为一个“锁”。
5. 所有实验都保留“一步回滚”的原始镜像，并在每次写入后读回比较。

## 代码改动概览

本 fork 相比上游增加或调整了：

- WinUSB/Preloader 连接和 Windows 设备枚举兼容性处理。
- 控制台日志降噪和 IO trace 开关。
- Carbonara payload 类型的设备流程。
- DA2 Lenovo storage-write gate 的精确、默认关闭、fail-closed 运行时补丁。
- 写入前检查补丁是否确实应用，避免误以为 DA 已解锁写权限。
- DA 写入窗口分块，适配本机 WinUSB 传输。
- 使用实验写入开关时强制新建 DA 会话，避免复用旧的 `.state`。
- `da seccfg` 子命令的 `--ptype`、WinUSB VID/PID 和 `--experimental-da-write` 参数。

默认不会启用实验写入补丁。只有明确传入 `--experimental-da-write` 才会请求它。

## 安全与使用范围

本项目只用于设备所有者或得到明确授权的维修、备份和研究。不要使用本工具处理不属于
自己的设备，不要分享 auth、证书、设备唯一 ID、分区备份或私钥。任何写入操作都有变砖
风险；尤其是 Preloader、LK、TEE、RPMB、OTP 和安全配置区域。
