# 纯 Rust 实现的 CryptoJS.AES.encrypt 和 CryptoJS.AES.decrypt

本仓库仅仅用作 [浅析 CryptoJS.AES 加解密过程](https://668000.xyz/archives/3/) 博文的 Rust 实现演示代码，并没有写的很严谨，**仅供学习使用，请不要将其用于生产环境**。

## EVP_BytesToKey 逻辑

 1. 将 password 转换成二进制 buffer
 2. 将 salt 转换成二进制 buffer，并确保 salt 是 8 位
 3. 初始化 key、iv、tmp 等二进制 buffer
 4. 进入 md5 加密循环：
  - 使用 md5 算法，依次传入 tmp、password 和 salt，计算得到新的 tmp
  - 使用 tmp 依次填充 key 和 iv
  - 如果两者没被填满，则继续循环，否则跳出循环
 5. 返回 key 和 iv

参考代码：[rowserify/EVP_BytesToKey](https://github.com/browserify/EVP_BytesToKey/blob/master/index.js)

## Cyptojs.AES 加密字符串解析

加密字符串是 base64 编码，其所对应的字节数组由三部分组成：

1. Salted__ 这八个字符对应的 ASCII 编码，占 8 个字节
2. 加密时用到的随机种子，占 8 个字节
3. 用 AES 算法（Rijndael 算法，CBC 模式，256 位密钥，128 位块）加密得到的字节数组