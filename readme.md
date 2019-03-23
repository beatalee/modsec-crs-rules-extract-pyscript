# 目录说明

## 主要是解决下面的问题
- 1, 解决全文中会生效的规则ID号替换
- 2, 解决所有规则的文本存储; 规则的信息提取。
- 3, 规则分类的赋予值


# 2018-8-10 
## 具体实施碰到的问题和解决方案
- 1, 会出现正则抓取规则 `%{}` 这样的字符内容除左（解决就是替换）
- 2, 记录所有生效的规则 `ID`, 不管该规则是执行的是全局变量修改还是全局的事件修改。
