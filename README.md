# 小米 Pad 7 Pro Droidspaces 内核维护项目

把版本配置、适配补丁、云端编译、模块核对和本地镜像打包放在同一个工程中。当前配置是 `muyu-os4.0.3.0`，对应 **OS4.0.3.0.XOYCNXM / Linux 6.1.157**。

同一系统版本以后可以运行一次维护入口：云端编译 → 下载产物 → 检查原厂模块兼容性 → 打包配套 `boot.img` 和 `vendor_boot.img`。不会自动刷写平板，也不会把原厂镜像或设备备份上传到 GitHub。

## 日常使用

本机工程已导入当前系统的原厂备份，位于被 Git 忽略的 `.local/baselines/muyu-os4.0.3.0/`。请保留这个目录，迁移电脑时另外复制；公开仓库和源码 ZIP 不含设备备份。

首次在一台新电脑使用，安装 Python 3.12、GitHub CLI，并登录一次：

```powershell
.\maintain.ps1 setup -Python 'C:\你的Python目录\python.exe'
gh auth login
```

以后同一系统重新编译和打包：

```powershell
.\maintain.ps1 rebuild
```

输出在 `.local/builds/<版本配置>/<本次构建>/`，包括配套镜像压缩包、检查报告和 SHA-256。原厂备份保留不动；`init_boot` 不替换。

也可以只在 GitHub Actions 中打开 **Build verified Droidspaces kernel → Run workflow**。保持默认 profile 即可。下载 `kernel-muyu-os4.0.3.0` 后解压，在本机打包：

```powershell
.\maintain.ps1 pack -Artifact 'C:\下载\解压后的构建产物'
```

只检查本机项目和基线：`./maintain.ps1 doctor`。

## 系统更新之后

**不能把“重新运行编译”当成任意新系统均可直接使用旧配置。** 同版本重编可以一键完成；跨系统版本要先生成一次新版本配置，保留以前的配置和备份。不同内核版本还需选择匹配的公共源码提交。

1. 官方更新并重启后，确认当前运行的是该版本的原厂内核；不要从旧的自定义内核生成所谓“新原厂基线”。
2. 有 Root 时，用 `./maintain.ps1 capture` 读取当前槽位的三个原始启动镜像及模块，保存到本机 `.local/captures/`。此操作只读取分区。没有 Root 时，使用该版本官方固件解出的镜像及模块。
3. 为新版本指定匹配的 `common` 源码提交，生成新 profile，见 [更新指南](docs/UPDATING.md)。不用重写补丁、脚本或打包逻辑。
4. 提交新的公开 profile 和公钥证书，再运行一次构建。任何模块 CRC、证书、内核版本或镜像布局不匹配，流程会停止，保留诊断记录。

如果小米更新带来新的 ABI 差异或改变内核布局，仍可能需要补丁适配；工具会报告问题，不能保证任何 OTA 都无需人工调整。

## 工程结构

| 路径 | 作用 |
|---|---|
| `profiles/*.json` | 按系统版本固定源码提交、原厂镜像哈希、模块和校验要求 |
| `profiles/certs/` | 原厂公开证书，不含私钥 |
| `configs/`、`patches/` | Droidspaces 功能配置和带来源记录的 SYSVIPC ABI 补丁 |
| `kernelkit/` | 模块检查、原厂基线管理、启动镜像打包 |
| `tools/maintain.py`、`maintain.ps1` | 统一命令入口 |
| `.github/workflows/build.yaml` | 编译、验证和产物留存 |
| `.github/workflows/check.yaml` | Windows / Linux 工具检查 |
| `.local/` | 仅本机保存的备份、产物、环境状态，不进入 Git |

## 构建与兼容性约束

- 源码 manifest、common、repo 工具和 GitHub Actions 均固定提交，Python 依赖固定版本。修改补丁或配置会改变产物身份；旧产物不能冒充新版本通过打包。
- 保留 MODVERSIONS、MODULE_SIG_PROTECT 和 CFI；不改 CRC、不强制加载模块、不关闭保护。
- CIFS 及其配套模块随内核编译。DNS 模块允许未签名，仅在无模块依赖、导入全部来自 vmlinux、且不导出受保护接口时通过。
- 新内核保留原厂公开证书，签名检查与原厂模块 CRC 检查自动执行。
- 缓存只含公开 Git 源码对象；不缓存构建目录或生成的签名私钥。云端仍会执行编译，缓存被回收时也能重新下载并构建。[GitHub 缓存说明](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
- 默认产物不含巨大的 vmlinux 调试文件。需要时勾选 `include_debug`。
- 原厂 AVB 属性、回滚索引、镜像大小、DTB、启动配置和无关驱动在本地打包时保留。生成的镜像使用 `NONE` 完整性 footer，需要已解锁的设备；不是小米官方签名。

**目前没有实机启动测试记录。** 离线检查不证明开机、硬件、KernelSU 或 Droidspaces 可以正常运行。当前 KernelSU 模块没有 CRC 版本表，会明确列入待实机验证项。

## 开发验证

```text
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tools/maintain.py doctor
```

历史的一次性工作流保留在 Git 提交历史中，新仓库只提供一个正式内核构建入口。
