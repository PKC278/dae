# 通过分组的链式代理

节点链接末尾可以追加一个 `group://` 跳，该节点便不再由本机直接拨号，而是通过
指定分组当前选中的节点到达。

```shell
node {
    # dae 拨号分组 "front"，由选中的前置节点承载到落地服务器的连接，
    # 再由落地服务器访问目标。
    landing: 'vless://uuid@landing.example.com:443#landing -> group://front'
}

group {
    front {
        filter: name(keyword: 'relay')
        policy: min_moving_avg
    }
    proxy {
        filter: name(landing)
        policy: fixed(0)
    }
}

routing {
    domain(geosite:geolocation-!cn) -> proxy
    fallback: direct
}
```

## 链接的阅读方式

各跳自左向右层叠，与 dae 已支持的固定链式链接（`'tuic://LINK -> vmess://LINK'`）
一致：最右侧的一跳由 dae 自己拨号，左侧的每一跳都通过其右侧的一跳到达。因此
分组跳必须写在链的末尾，它承载写在它之前的全部跳。

固定链式代理与分组跳可以组合：

```shell
node {
    landing: 'vless://uuid@landing.example.com:443 -> socks5://127.0.0.1:1080 -> group://front'
}
```

## 分组带来的能力

分组保留自己的 filter、policy 与健康检查，前置跳因此跟随分组的实时选择：选中的
前置节点失效后，下一条经过该链式节点的连接会改用分组新选中的节点，链式节点本身
无需改动。

链式节点按整条链路做健康检查，因此它的延迟与可用性反映连接真实经过的路径，包含
前置跳。

## 约束

- 跳中指定的分组必须已在配置中定义。允许通过 `direct`，效果等同于直接拨号。
- 链不得直接或经由其他分组回到承载它的分组。dae 会报告该环路并拒绝启动。
- 一条节点链接最多包含一个分组跳，且必须位于末尾。
- 分组名含空格时需做百分号编码：`group://my%20front`。
- 链式节点上的 `tfo` 会被忽略：该节点不会建立自己的套接字，TCP Fast Open 属于
  承载它的分组中的节点。
