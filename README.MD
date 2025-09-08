# 这是一个工作量证明系统的demo

## 使用区块链原理开发的简易工作量证明系统

1、前端一个前置页面，用于工作量没有x-sign的页面请求停留；

2、在停留页面由后端渲染一个当前用户ip地址和后端用的今日起始区块和公钥字符串等信息

3、前端页面开始制作第二个区块，计算完成后，把各种数据打包用公钥加密后给防火墙后端校验；

4、校验通过后，防火墙后端把x-sign=前端的加密串写到cookie之类的；然后跳转到正确的页面；



## 如何运行：
```sh
pnpm install
pnpm dev
```

## 浏览器访问
http://127.0.0.1:3000?next=/text


# 你也可以查看工作原理简单demo
[点击查看](./docs/example.html)

```
git clone https://github.com/pcloth/pow-verification-system.js.git
```

然后直接浏览器打开docs/example.html查看精简版例子