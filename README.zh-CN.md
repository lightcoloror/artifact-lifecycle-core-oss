# Artifact Lifecycle Core 中文使用说明

这是一个离线、默认只生成计划、失败即关闭的产物生命周期核心。它提供
Manifest、有限扫描、解释、不可变计划、计划校验、合成隔离/恢复和操作回执，
但不替代项目自己的业务状态机。

## 从源码运行

```powershell
python artifact_lifecycle_core.py doctor
python run_tests.py
python run_tests.py --clean-copy
```

## 离线构建和安装

本地已有 `setuptools` 时可执行：

```powershell
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m venv <venv>
<venv>\Scripts\python.exe -m pip install --no-index --no-deps <wheel>
<venv>\Scripts\local-artifacts.exe doctor
```

Linux/macOS 的入口名称为 `local-artifacts` 和 `local-artifacts-demo`。

## 合成演示

```powershell
local-artifacts-demo --workspace <empty-or-dedicated-root> --run-id demo-01
```

演示只操作该命令创建的合成目录，完成 scan、explain、plan、verify、
quarantine 和 restore。重复同一 `run-id` 时只验证已有回执。部分失败会保留
证据并要求使用新的 `run-id`；不会自动清理或扩大范围。

## 安全边界

- `cleanup_mode=plan_only`，`automatic_purge=false`。
- `apply-purge` 永久返回拒绝。
- 真实隔离仍需精确、未过期且与计划哈希绑定的人工批准。
- junction/symlink/reparse、跨卷、路径越界、活动状态、引用不明、计划漂移、
  重建证据不完整和 Access Denied 均失败即关闭。
- doctor 通过只证明本地合同和运行入口可用，不证明在线、真实使用或发布完成。

本公开源代码版本采用 Apache-2.0，许可证边界见 `LICENSE`。
本机工具清单和历史任务回执已从公开版排除。合成验证的结果见发布记录。
