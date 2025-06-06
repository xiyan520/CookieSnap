# 🍚 CookieSnap

**CookieSnap** 是一个轻量级的浏览器扩展程序，用于快速提取并复制当前网页的 Cookie 信息，适用于开发调试、接口测试等场景。

---

## 🚀 功能特点

* 一键提取当前标签页的 Cookie
* 自动格式化为标准 `key=value;` 样式
* 适用于浏览器插件（Chrome / Edge 等）
* 操作简单，无需开发经验

---

## 📆 安装方法

1. 克隆或下载本项目到本地：

   ```bash
   git clone https://github.com/xiyan520/CookieSnap.git
   ```
2. 打开浏览器地址栏输入：

   ```
   chrome://extensions/
   ```
3. 启用右上角“开发者模式”
4. 点击“加载已解压的扩展程序”
5. 选择项目目录中的 `CookieSnap` 文件夹

---

## 🛏️ 使用方法

1. 打开任意网页（例如 `https://example.com`）
2. 点击浏览器工具栏的 CookieSnap 图标
3. 弹出窗口将显示当前页面的所有 Cookie
4. 点击“复制”按钮将其复制到剪贴板

---

## 📋 输出示例（Cookie 格式）

```text
sessionid=abcd1234; token=xyz789; theme=dark;
```

---

## 🧪 应用示例（在 Python 中使用）

```python
import requests

headers = {
    "Cookie": "sessionid=abcd1234; token=xyz789;",
    "User-Agent": "Mozilla/5.0"
}

res = requests.get("https://example.com", headers=headers)
print(res.text)
```

---

## 🔒 权限声明

插件请求以下权限用于读取网页 Cookie：

```json
"permissions": [
  "cookies",
  "activeTab",
  "tabs",
  "<all_urls>"
]
```

请仅在合法合规的前提下使用，严禁采集他人隐私信息。

---
