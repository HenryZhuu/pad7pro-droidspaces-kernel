# 系统更新与新版本配置

## 同一系统版本重编

在已导入对应基线、已安装 Python 环境并登录 GitHub CLI 的电脑中：

```powershell
.\maintain.ps1 rebuild -Profile muyu-os4.0.3.0
```

这会串起云端编译、等待结果、下载、原厂模块校验和镜像打包。编译失败就停止，不会刷写设备。源码下载缓存只用于加速，丢失缓存不影响可构建性。

## 准备新系统基线

先官方更新并重启，核对版本与内核。已有 Root 时：

```powershell
.\maintain.ps1 capture -Adb 'D:\platform-tools\adb.exe'
```

记录终端显示的采集目录。里面是当前活动槽位的 `boot.img`、`vendor_boot.img`、`init_boot.img`、原厂模块归档和 `device.json`。设备上的临时副本会在成功采集后删除。没有 Root 或采集中断时，使用官方固件提取文件，或恢复 Root 后重试；不要用不明来源的镜像代替。

选择与新系统内核家族及版本匹配的公共源码提交，随后运行：

```powershell
.venv\Scripts\python.exe tools\maintain.py --profile muyu-os4.0.3.0 new-profile `
  --capture '.local\captures\实际采集目录' `
  --id 'muyu-新版本标识' `
  --common-commit '完整的40位公共内核提交SHA'
```

上面的“新版本标识”和 SHA 是要替换的说明文字，不能直接照抄。profile ID 使用小写字母、数字、点和连字符。内核 manifest 或工具链也变更时，再加 `--manifest-commit` 固定对应提交。

工具会从原始 boot 中查找公钥证书，与原厂模块签名交叉确认，生成公开 profile 与公开证书，并在本机导入私有基线。找不到唯一匹配证书、内核家族不再是 Android 14 / 6.1、或布局不支持时会停止，需要先适配。

审核新 profile、源码提交和补丁是否仍适用，再把 `profiles/` 的公开变更提交至 GitHub。新内核版本不一定存在无需额外修改的 ABI 兼容公共源码；编译通过也不等于已适配小米的所有变化。

之后新版本同样只需要：

```powershell
.\maintain.ps1 rebuild -Profile 'muyu-实际新版本标识'
```

## 新电脑导入已有基线

把原有 `.local/baselines/` 私下复制过去，或根据已提交 profile 导入校验一致的原始文件：

```text
python tools/maintain.py --profile muyu-os4.0.3.0 import-baseline --boot 原boot路径 --vendor-boot 原vendor_boot路径 --init-boot 原init_boot路径 --modules-tar 原厂模块tar路径
```

文件哈希必须与 profile 一致。原始基线不会被覆盖。不要把 `.local/` 或完整固件提交到公开仓库。

## 构建故障

- 源码补丁应用失败：公共源码结构已变化，更新 patch；不要强制忽略。
- 模块 CRC 不一致：先检查 profile、固件和模块是否配套，再适配或重编相关驱动；不要改 CRC 或强制加载。
- 原厂公钥不匹配：重新确认该版本原始 boot 与模块。
- 产物身份不匹配：下载与当前 profile 和补丁一致的新产物；旧产物不能直接进入打包。
- KernelSU 没有版本表：保留明确待实机验证状态，不能用离线检查替代实际启动。

刷写前，另外确认设备版本、当前活动槽位、BL 解锁状态和可用的原厂恢复镜像。本工程不自动执行刷写。
