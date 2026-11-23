# pairwise-http-smuggling

## 领域

安全

## 主题

HTTP 请求走私

## 说明

拒绝歧义头、统一解析器与 TE 禁用。

初始状态下 `security/http_smuggling.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
