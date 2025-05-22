# CodeQL自定义规则测试环境

这个目录包含用于测试CodeQL自定义规则的示例代码，每个文件都包含特定类型的安全漏洞。

## 示例文件说明

1. **pickle_vuln.py** - 包含不安全的pickle反序列化漏洞
   - 该示例展示了直接反序列化来自网络套接字的数据，可被UnsafeDeserialization_pickle.ql规则检测

2. **command_injection.py** - 包含命令注入漏洞
   - 该示例展示了从环境中获取数据（如当前目录）并与用户输入组合后通过os.system执行，可被CommandInjectiontest.ql规则检测

3. **resource_exhaustion.py** - 包含资源耗尽漏洞
   - 该示例展示了不设置超时参数的网络请求，结合正则表达式处理，可被ResourceExhaustion.ql规则检测

## 使用方法

1. 在项目根目录运行 `./test_custom_rules.sh` 脚本
2. 该脚本会：
   - 检查每个规则的语法正确性
   - 为测试代码创建CodeQL数据库
   - 在测试数据库上运行每个规则
   - 输出分析结果

## 注意事项

- 这些示例代码**仅用于测试目的**，包含故意引入的安全漏洞
- 请不要在生产环境中使用这些代码
- 如需修改测试代码以验证规则的其他方面，请保持漏洞的本质不变 