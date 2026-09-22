# Chain proxy through a group

A node link may end in a `group://` hop. The node is then reached through
whichever node that group currently selects, instead of being dialed from the
machine running dae.

```shell
node {
    # dae dials the group "front", the selected front node carries the
    # connection to the landing server, and the landing server reaches the
    # target.
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

## Reading a chain link

Hops are layered left to right, exactly like the fixed chain links dae already
supports (`'tuic://LINK -> vmess://LINK'`): the rightmost hop is the one dae
dials itself, and every hop to its left is reached through the hop on its
right. The group hop therefore has to be the last element of the chain, because
it carries everything written before it.

A fixed chain and a group hop combine:

```shell
node {
    landing: 'vless://uuid@landing.example.com:443 -> socks5://127.0.0.1:1080 -> group://front'
}
```

## What the group contributes

The group keeps its own filter, policy and health checks, so the front hop
follows the group's live selection: when the selected front node dies, the next
connection through the chained node takes whichever node the group picks next,
with no change to the chained node itself.

The chained node runs its own health checks over the whole chain, so its
latency and availability describe the path a connection actually takes, front
hop included.

## Rules

- The group named by the hop must be defined in the configuration. Chaining
  through `direct` is accepted and is equivalent to dialing the node directly.
- A chain must not loop back into a group that carries it, directly or through
  other groups. dae reports the loop and refuses to start.
- A node link carries at most one group hop, and it must be the last one.
- Percent-encode a group name that contains spaces: `group://my%20front`.
- `tfo` on a chained node is ignored: the node opens no socket of its own, so
  TCP Fast Open belongs to the nodes of the group that carries it.
