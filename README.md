> 讲师：李振良(微信: init1024)
>
> 官方网站： http://www.ctnrs.com  
>
> 名称：《K8s主流网络方案实战》 
> ![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/wx.png)



# K8s主流网络方案实战

## 4.1 网络基础知识

### 1、公司网络架构



![](http://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/network-arch1.png)

- **路由器：**网络出口
- **核心层：**主要完成数据高效转发、链路备份等
- **汇聚层：**网络策略、安全、工作站交换机的接入、VLAN之间通信等功能
- **接入层：**工作站的接入

### 2、交换技术

有想过局域网内主机怎么通信的？主机访问外网又是怎么通信的？

想要搞懂这些问题得从交换机、路由器讲起。

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/switch.png)

交换机工作在OSI参考模型的第二次，即数据链路层。交换机拥有一条高带宽的背部总线交换矩阵，在同一时间可进行多个端口对之间的数据传输。

**交换技术分为2层和3层：**

- 2层：主要用于小型局域网，仅支持在数据链路层转发数据，对工作站接入。

- 3层：三层交换技术诞生，最初是为了解决广播域的问题，多年发展，三层交换机书已经成为构建中大型网络的主要力量。

**广播域**

交换机在转发数据时会先进行广播，这个广播可以发送的区域就是一个广播域。交换机之间对广播帧是透明的，所以交换机之间组成的网络是一个广播域。

路由器的一个接口下的网络是一个广播域，所以路由器可以隔离广播域。

**ARP（地址解析协议**，在IPV6中用NDP替代）

发送这个广播帧是由ARP协议实现，ARP是通过IP地址获取物理地址的一个TCP/IP协议。

**三层交换机**

前面讲的二层交换机只工作在数据链路层，路由器则工作在网络层。而功能强大的三层交换机可同时工作在数据链路层和网络层，并根据 MAC地址或IP地址转发数据包。

**VLAN（Virtual Local Area Network）：虚拟局域网**

VLAN是一种将局域网设备从逻辑上划分成一个个网段。

一个VLAN就是一个广播域，VLAN之间的通信是通过第3层的路由器来完成的。VLAN应用非常广泛，基本上大部分网络项目都会划分vlan。

VLAN的主要好处：

- 分割广播域，减少广播风暴影响范围。
- 提高网络安全性，根据不同的部门、用途、应用划分不同网段

### 3、路由技术

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/router.png)

路由器主要分为两个端口类型：LAN口和WAN口

- WAN口：配置公网IP，接入到互联网，转发来自LAN口的IP数据包。

- LAN口：配置内网IP（网关），连接内部交换机。

**路由器是连接两个或多个网络的硬件设备，将从端口上接收的数据包，根据数据包的目的地址智能转发出去。**

**路由器的功能：**

- 路由
- 转发
- 隔离子网
- 隔离广播域

路由器是互联网的枢纽，是连接互联网中各个局域网、广域网的设备，相比交换机来说，路由器的数据转发很复杂，它会根据目的地址给出一条最优的路径。那么路径信息的来源有两种：**动态路由和静态路由。**

**静态路由：**指人工手动指定到目标主机的地址然后记录在路由表中，如果其中某个节点不可用则需要重新指定。

**动态路由：**则是路由器根据动态路由协议自动计算出路径永久可用，能实时地**适应网络结构**的变化。

常用的动态路由协议：

- RIP（ Routing Information Protocol ，路由信息协议）

- OSPF（Open Shortest Path First，开放式最短路径优先）

- BGP（Border Gateway Protocol，边界网关协议）



### 4、OSI七层模型

OSI（Open System Interconnection）是国际标准化组织（ISO）制定的一个用于计算机或通信系统间互联的标准体系，一般称为OSI参考模型或七层模型。 

| **层次** | **名称**   | **功能**                                     | **协议数据单元（PDU）** | **常见协议**        |
| -------- | ---------- | -------------------------------------------- | ----------------------- | ------------------- |
| 7        | 应用层     | 为用户的应用程序提供网络服务，提供一个接口。 | 数据                    | HTTP、FTP、Telnet   |
| 6        | 表示层     | 数据格式转换、数据加密/解密                  | 数据单元                | ASCII               |
| 5        | 会话层     | 建立、管理和维护会话                         | 数据单元                | SSH、RPC            |
| 4        | 传输层     | 建立、管理和维护端到端的连接                 | 段/报文                 | TCP、UDP            |
| 3        | 网络层     | IP选址及路由选择                             | 分组/包                 | IP、ICMP、RIP、OSPF |
| 2        | 数据链路层 | 硬件地址寻址，差错效验等。                   | 帧                      | ARP、WIFI           |
| 1        | 物理层     | 利用物理传输介质提供物理连接，传送比特流。   | 比特流                  | RJ45、RJ11          |

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/osi-table.png)

### 5、TCP/UDP协议

TCP（Transmission Control Protocol，传输控制协议），面向连接协议，双方先建立可靠的连接，再发送数据。适用于传输数据量大，可靠性要求高的应用场景。

UDP（User Data Protocol，用户数据报协议），面向非连接协议，不与对方建立连接，直接将数据包发送给对方。适用于一次只传输少量的数据，可靠性要求低的应用场景。相对TCP传输速度快。

## 4.2 Kubernetes网络模型

Kubernetes 要求所有的网络插件实现必须满足如下要求：

- 一个Pod一个IP
- 所有的 Pod 可以与任何其他 Pod 直接通信，无需使用 NAT 映射
- 所有节点可以与所有 Pod 直接通信，无需使用 NAT 映射
- Pod 内部获取到的 IP 地址与其他 Pod 或节点与其通信时的 IP 地址是同一个。

### 1、Docker容器网络模型

先看下Linux网络名词：

- **网络的命名空间：**Linux在网络栈中引入网络命名空间，将独立的网络协议栈隔离到不同的命令空间中，彼此间无法通信；Docker利用这一特性，实现不同容器间的网络隔离。

- **Veth设备对：**Veth设备对的引入是为了实现在不同网络命名空间的通信。

- **Iptables/Netfilter：**Docker使用Netfilter实现容器网络转发。

- **网桥：**网桥是一个二层网络设备，通过网桥可以将Linux支持的不同的端口连接起来，并实现类似交换机那样的多对多的通信。

- **路由：**Linux系统包含一个完整的路由功能，当IP层在处理数据发送或转发的时候，会使用路由表来决定发往哪里。

Docker容器网络示意图如下：

<img src="https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/docker-network.png" style="zoom: 80%;" />



### 2、Pod 网络

**问题：**Pod是K8S最小调度单元，一个Pod由一个容器或多个容器组成，当多个容器时，怎么都用这一个Pod IP？

**实现：**k8s会在每个Pod里先启动一个infra container小容器，然后让其他的容器连接进来这个网络命名空间，然后其他容器看到的网络试图就完全一样了。即网络设备、IP地址、Mac地址等。这就是解决网络共享的一种解法。在Pod的IP地址就是infra container的IP地址。

<img src="https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/c-to-c.png" style="zoom: 80%;" />



在 Kubernetes 中，每一个 Pod 都有一个真实的 IP 地址，并且每一个 Pod 都可以使用此 IP 地址与 其他 Pod 通信。

Pod之间通信会有两种情况：

- 两个Pod在同一个Node上
- 两个Pod在不同Node上

**先看下第一种情况：两个Pod在同一个Node上**

同节点Pod之间通信道理与Docker网络一样的，如下图：

<img src="https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/pod-to-pod-2.gif" style="zoom:50%;" />

1. 对 Pod1 来说，eth0 通过虚拟以太网设备（veth0）连接到 root namespace；
2. 网桥 cbr0 中为 veth0 配置了一个网段。一旦数据包到达网桥，网桥使用ARP 协议解析出其正确的目标网段 veth1；
3. 网桥 cbr0 将数据包发送到 veth1；
4. 数据包到达 veth1 时，被直接转发到 Pod2 的 network namespace 中的 eth0 网络设备。



**再看下第二种情况：两个Pod在不同Node上**

K8S网络模型要求Pod IP在整个网络中都可访问，这种需求是由第三方网络组件实现。

<img src="https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/pod-to-pod-3.gif" style="zoom:50%;" />

### 3、CNI（容器网络接口）

CNI（Container Network Interface，容器网络接口)：是一个容器网络规范，Kubernetes网络采用的就是这个CNI规范，CNI实现依赖两种插件，一种CNI Plugin是负责容器连接到主机，另一种是IPAM负责配置容器网络命名空间的网络。

CNI插件默认路径：

```
# ls /opt/cni/bin/
```

地址：https://github.com/containernetworking/cni

当你在宿主机上部署Flanneld后，flanneld 启动后会在每台宿主机上生成它对应的CNI 配置文件（它其实是一个 ConfigMap），从而告诉Kubernetes，这个集群要使用 Flannel 作为容器网络方案。

CNI配置文件路径：

```
/etc/cni/net.d/10-flannel.conflist
```

当 kubelet 组件需要创建 Pod 的时候，先调用dockershim它先创建一个 Infra 容器。然后调用 CNI 插件为 Infra 容器配置网络。

这两个路径在kubelet启动参数中定义： 

```
 --network-plugin=cni \
 --cni-conf-dir=/etc/cni/net.d \
 --cni-bin-dir=/opt/cni/bin
```

## 4.3 Kubernetes网络组件之 Flannel

Flannel是CoreOS维护的一个网络组件，Flannel为每个Pod提供全局唯一的IP，Flannel使用ETCD来存储Pod子网与Node IP之间的关系。flanneld守护进程在每台主机上运行，并负责维护ETCD信息和路由数据包。

### 1、Flannel 部署

 https://github.com/coreos/flannel 

```
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

### 2、 Flannel工作模式及原理

Flannel支持多种数据转发方式：

- UDP：最早支持的一种方式，由于性能最差，目前已经弃用。
- VXLAN：Overlay Network方案，源数据包封装在另一种网络包里面进行路由转发和通信
- Host-GW：Flannel通过在各个节点上的Agent进程，将容器网络的路由信息刷到主机的路由表上，这样一来所有的主机都有整个容器网络的路由数据了。

#### VXLAN

```
# kubeadm部署指定Pod网段
kubeadm init --pod-network-cidr=10.244.0.0/16

# 二进制部署指定
cat /opt/kubernetes/cfg/kube-controller-manager.conf
--allocate-node-cidrs=true \
--cluster-cidr=10.244.0.0/16 \
```



```
# kube-flannel.yml
net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }
```



为了能够在二层网络上打通“隧道”，VXLAN 会在宿主机上设置一个特殊的网络设备作为“隧道”的两端。这个设备就叫作 VTEP，即：VXLAN Tunnel End Point（虚拟隧道端点）。下图flannel.1的设备就是VXLAN所需的VTEP设备。示意图如下：

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/flanneld-vxlan.png)



如果Pod 1访问Pod 2，源地址10.244.1.10，目的地址10.244.2.10 ，数据包传输流程如下：

1. **容器路由：**容器根据路由表从eth0发出

   ```
   / # ip route
   default via 10.244.0.1 dev eth0 
   10.244.0.0/24 dev eth0 scope link  src 10.244.0.45 
   10.244.0.0/16 via 10.244.0.1 dev eth0 
   ```

 2. **主机路由：**数据包进入到宿主机虚拟网卡cni0，根据路由表转发到flannel.1虚拟网卡，也就是，来到了隧道的入口。

    ```
    # ip route
    default via 192.168.31.1 dev ens33 proto static metric 100 
    10.244.0.0/24 dev cni0 proto kernel scope link src 10.244.0.1 
    10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink 
    10.244.2.0/24 via 10.244.2.0 dev flannel.1 onlink 
    ```

  3. **VXLAN封装：**而这些VTEP设备（二层）之间组成二层网络必须要知道目的MAC地址。这个MAC地址从哪获取到呢？其实在flanneld进程启动后，就会自动添加其他节点ARP记录，可以通过ip命令查看，如下所示：

     ```
     # ip neigh show dev flannel.1
     10.244.1.0 lladdr ca:2a:a4:59:b6:55 PERMANENT
     10.244.2.0 lladdr d2:d0:1b:a7:a9:cd PERMANENT
     ```

4. **二次封包：**知道了目的MAC地址，封装二层数据帧（容器源IP和目的IP）后，对于宿主机网络来说这个帧并没有什么实际意义。接下来，Linux内核还要把这个数据帧进一步封装成为宿主机网络的一个普通数据帧，好让它载着内部数据帧，通过宿主机的eth0网卡进行传输。

   ![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/vxlan-pkg.png)

5. **封装到UDP包发出去：**现在能直接发UDP包嘛？到目前为止，我们只知道另一端的flannel.1设备的MAC地址，却不知道对应的宿主机地址是什么。

   flanneld进程也维护着一个叫做FDB的转发数据库，可以通过bridge fdb命令查看：

   ```
   # bridge fdb show  dev flannel.1
   
      d2:d0:1b:a7:a9:cd dst 192.168.31.61 self permanent
      ca:2a:a4:59:b6:55 dst 192.168.31.63 self permanent
   ```
   
   可以看到，上面用的对方flannel.1的MAC地址对应宿主机IP，也就是UDP要发往的目的地。使用这个目的IP进行封装。
   
6. **数据包到达目的宿主机：**Node1的eth0网卡发出去，发现是VXLAN数据包，把它交给flannel.1设备。flannel.1设备则会进一步拆包，取出原始二层数据帧包，发送ARP请求，经由cni0网桥转发给container。
#### Host-GW

host-gw模式相比vxlan简单了许多， 直接添加路由，将目的主机当做网关，直接路由原始封包。 

下面是示意图：

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/flanneld-hostgw.png)

```
# kube-flannel.yml

net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "host-gw"
      }
    }
```

当你设置flannel使用host-gw模式,flanneld会在宿主机上创建节点的路由表：
```
# ip route

default via 192.168.31.1 dev ens33 proto static metric 100 
10.244.0.0/24 dev cni0 proto kernel scope link src 10.244.0.1 
10.244.1.0/24 via 192.168.31.63 dev ens33 
10.244.2.0/24 via 192.168.31.61 dev ens33 
192.168.31.0/24 dev ens33 proto kernel scope link src 192.168.31.62 metric 100 
```
目的 IP 地址属于 10.244.1.0/24 网段的 IP 包，应该经过本机的 eth0 设备发出去（即：dev eth0）；并且，它下一跳地址是 192.168.31.63（即：via 192.168.31.63）。

一旦配置了下一跳地址，那么接下来，当 IP 包从网络层进入链路层封装成帧的时候，eth0 设备就会使用下一跳地址对应的 MAC 地址，作为该数据帧的目的 MAC 地址。

而 Node 2 的内核网络栈从二层数据帧里拿到 IP 包后，会“看到”这个 IP 包的目的 IP 地址是 10.244.1.20，即 container-2 的 IP 地址。这时候，根据 Node 2 上的路由表，该目的地址会匹配到第二条路由规则（也就是 10.244.1.0 对应的路由规则），从而进入 cni0 网桥，进而进入到 container-2 当中。

## 4.4 Kubernetes网络方案之 Calico

Calico是一个纯三层的数据中心网络方案，Calico支持广泛的平台，包括Kubernetes、OpenStack等。

Calico 在每一个计算节点利用 Linux Kernel 实现了一个高效的虚拟路由器（ vRouter） 来负责数据转发，而每个 vRouter 通过 BGP 协议负责把自己上运行的 workload 的路由信息向整个 Calico 网络内传播。

此外，Calico  项目还实现了 Kubernetes 网络策略，提供ACL功能。

### 1、BGP概述

实际上，Calico项目提供的网络解决方案，与Flannel的host-gw模式几乎一样。也就是说，Calico也是基于路由表实现容器数据包转发，但不同于Flannel使用flanneld进程来维护路由信息的做法，而Calico项目使用BGP协议来自动维护整个集群的路由信息。

BGP英文全称是Border Gateway Protocol，即边界网关协议，它是一种自治系统间的动态路由发现协议，与其他 BGP 系统交换网络可达信息。 

为了能让你更清楚理解BGP，举个例子：

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/bgp.png)

在这个图中，有两个自治系统（autonomous system，简称为AS）：AS 1 和 AS 2。

在互联网中，一个自治系统(AS)是一个有权自主地决定在本系统中应采用何种路由协议的小型单位。这个网络单位可以是一个简单的网络也可以是一个由一个或多个普通的网络管理员来控制的网络群体，它是一个单独的可管理的网络单元（例如一所大学，一个企业或者一个公司个体）。一个自治系统有时也被称为是一个路由选择域（routing domain）。一个自治系统将会分配一个全局的唯一的16位号码，有时我们把这个号码叫做自治系统号（ASN）。

在正常情况下，自治系统之间不会有任何来往。如果两个自治系统里的主机，要通过 IP 地址直接进行通信，我们就必须使用路由器把这两个自治系统连接起来。BGP协议就是让他们互联的一种方式。

###  2、Calico BGP实现

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/calico.png)

在了解了 BGP 之后，Calico 项目的架构就非常容易理解了，Calico主要由三个部分组成：

- Felix：以DaemonSet方式部署，运行在每一个Node节点上，主要负责维护宿主机上路由规则以及ACL规则。
- BGP Client（BIRD）：主要负责把 Felix 写入 Kernel 的路由信息分发到集群 Calico 网络。
- Etcd：分布式键值存储，保存Calico的策略和网络配置状态。
- calicoctl：允许您从简单的命令行界面实现高级策略和网络。

### 3、Calico 部署

```
curl https://docs.projectcalico.org/v3.9/manifests/calico-etcd.yaml -o calico.yaml
```

下载完后还需要修改里面配置项：

具体步骤如下：

- 配置连接etcd地址，如果使用https，还需要配置证书。（ConfigMap，Secret）
- 根据实际网络规划修改Pod CIDR（CALICO_IPV4POOL_CIDR）
- 选择工作模式（CALICO_IPV4POOL_IPIP），支持BGP，IPIP

修改完后应用清单：

```
# kubectl apply -f calico.yaml
# kubectl get pods -n kube-system
```

### 4、Calico 管理工具

下载工具：https://github.com/projectcalico/calicoctl/releases

```
# wget -O /usr/local/bin/calicoctl https://github.com/projectcalico/calicoctl/releases/download/v3.9.1/calicoctl
# chmod +x /usr/local/bin/calicoctl
```

```
# mkdir /etc/calico
# vim /etc/calico/calicoctl.cfg  
apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  datastoreType: "etcdv3"
  etcdEndpoints: "https://192.168.31.61:2379,https://192.168.31.62:2379,https://192.168.31.63:2379"
  etcdKeyFile: "/opt/etcd/ssl/server-key.pem"
  etcdCertFile: "/opt/etcd/ssl/server.pem"
  etcdCACertFile: "/opt/etcd/ssl/ca.pem"
```

使用calicoctl查看服务状态：

```
# calicoctl node status
Calico process is running.

IPv4 BGP status
+---------------+-------------------+-------+----------+-------------+
| PEER ADDRESS  |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+---------------+-------------------+-------+----------+-------------+
| 192.168.31.62 | node-to-node mesh | up    | 09:09:20 | Established |
| 192.168.31.63 | node-to-node mesh | up    | 09:09:20 | Established |
+---------------+-------------------+-------+----------+-------------+
```

```
# calicoctl get nodes
NAME         
k8s-master   
k8s-node1    
k8s-node2  
```

查看 IPAM的IP地址池：

```
# calicoctl get ippool -o wide
```

### 5、Calico BGP 原理剖析

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/calico-bgp.png)

Pod 1 访问 Pod 2大致流程如下：

1. 数据包从容器1出到达Veth Pair另一端（宿主机上，以cali前缀开头）；

2. 宿主机根据路由规则，将数据包转发给下一跳（网关）；
3. 到达Node2，根据路由规则将数据包转发给cali设备，从而到达容器2。

路由表：

```
# node1
10.244.36.65 dev cali4f18ce2c9a1 scope link 
10.244.169.128/26 via 192.168.31.63 dev ens33 proto bird 
10.244.235.192/26 via 192.168.31.61 dev ens33 proto bird 
# node2
10.244.169.129 dev calia4d5b2258bb scope link 
10.244.36.64/26 via 192.168.31.62 dev ens33 proto bird
10.244.235.192/26 via 192.168.31.61 dev ens33 proto bird 
```

其中，这里最核心的“下一跳”路由规则，就是由 Calico 的 Felix 进程负责维护的。这些路由规则信息，则是通过 BGP Client 也就是 BIRD 组件，使用 BGP 协议传输而来的。

不难发现，Calico 项目实际上将集群里的所有节点，都当作是边界路由器来处理，它们一起组成了一个全连通的网络，互相之间通过 BGP 协议交换路由规则。这些节点，我们称为 BGP Peer。

### 6、Route Reflector 模式（RR）

https://docs.projectcalico.org/master/networking/bgp 

Calico 维护的网络在默认是（Node-to-Node Mesh）全互联模式，Calico集群中的节点之间都会相互建立连接，用于路由交换。但是随着集群规模的扩大，mesh模式将形成一个巨大服务网格，连接数成倍增加。

这时就需要使用 Route Reflector（路由器反射）模式解决这个问题。

确定一个或多个Calico节点充当路由反射器，让其他节点从这个RR节点获取路由信息。

具体步骤如下：

**1、关闭 node-to-node BGP网格**

添加 default BGP配置，调整 nodeToNodeMeshEnabled和asNumber：

```
 cat << EOF | calicoctl create -f -
 apiVersion: projectcalico.org/v3
 kind: BGPConfiguration
 metadata:
   name: default
 spec:
   logSeverityScreen: Info
   nodeToNodeMeshEnabled: false  
   asNumber: 63400
EOF
```

ASN号可以通过获取 # calicoctl get nodes --output=wide

**2、配置指定节点充当路由反射器**

为方便让BGPPeer轻松选择节点，通过标签选择器匹配。

给路由器反射器节点打标签：

```
kubectl label node my-node route-reflector=true
```

然后配置路由器反射器节点routeReflectorClusterID：

```
apiVersion: projectcalico.org/v3
kind: Node
metadata:
  annotations:
    projectcalico.org/kube-labels: '{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/os":"linux","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"k8s-node2","kubernetes.io/os":"linux"}'
  creationTimestamp: null
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: k8s-node2
    kubernetes.io/os: linux
  name: k8s-node2
spec:
  bgp:
    ipv4Address: 192.168.31.63/24
    routeReflectorClusterID: 244.0.0.1   # 集群ID
  orchRefs:
  - nodeName: k8s-node2
    orchestrator: k8s
```

现在，很容易使用标签选择器将路由反射器节点与其他非路由反射器节点配置为对等：

```
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == 'true'
```

查看节点的BGP连接状态：

```
calicoctl node status
```

### 7、IPIP模式

在前面提到过，Flannel host-gw 模式最主要的限制，就是要求集群宿主机之间是二层连通的。而这个限制对于 Calico 来说，也同样存在。

修改为IPIP模式：

```
# calicoctl get ipPool -o yaml > ipip.yaml
# vi ipip.yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  blockSize: 26
  cidr: 10.244.0.0/16
  ipipMode: Always
  natOutgoing: true

# calicoctl apply -f ipip.yaml
# calicoctl get ippool -o wide
```

IPIP示意图：

![](https://k8s-1252881505.cos.ap-beijing.myqcloud.com/k8s-2/calico-ipip.png)

Pod 1 访问 Pod 2大致流程如下：

1. 数据包从容器1出到达Veth Pair另一端（宿主机上，以cali前缀开头）；
2. 进入IP隧道设备（tunl0），由Linux内核IPIP驱动封装在宿主机网络的IP包中（新的IP包目的地之是原IP包的下一跳地址，即192.168.31.63），这样，就成了Node1 到Node2的数据包；
3. 数据包经过路由器三层转发到Node2；
4. Node2收到数据包后，网络协议栈会使用IPIP驱动进行解包，从中拿到原始IP包；
5. 然后根据路由规则，根据路由规则将数据包转发给cali设备，从而到达容器2。

路由表：

```
# node1
10.244.36.65 dev cali4f18ce2c9a1 scope link 
10.244.169.128/26 via 192.168.31.63 dev tunl0 proto bird onlink 
# node2
10.244.169.129 dev calia4d5b2258bb scope link 
10.244.36.64/26 via 192.168.31.62 dev tunl0 proto bird onlink 
```

不难看到，当 Calico 使用 IPIP 模式的时候，集群的网络性能会因为额外的封包和解包工作而下降。所以建议你将所有宿主机节点放在一个子网里，避免使用 IPIP。

### 8、CNI 网络方案优缺点及最终选择

先考虑几个问题：

- 需要细粒度网络访问控制？
- 追求网络性能？
- 服务器之前是否可以跑BGP协议？
- 集群规模多大？
- 是否有维护能力？



### 小话题：办公网络与K8S网络如何互通



## 4.5 网络策略

### 1、为什么需要网络隔离？

CNI插件插件解决了不同Node节点Pod互通问题，从而形成一个扁平化网络，默认情况下，Kubernetes 网络允许所有 Pod 到 Pod 的流量，在一些场景中，我们不希望Pod之间默认相互访问，例如：

- 应用程序间的访问控制。例如微服务A允许访问微服务B，微服务C不能访问微服务A
- 开发环境命名空间不能访问测试环境命名空间Pod
- 当Pod暴露到外部时，需要做Pod白名单
- 多租户网络环境隔离

所以，我们需要使用network policy对Pod网络进行隔离。支持对Pod级别和Namespace级别网络访问控制。

Pod网络入口方向隔离

- 基于Pod级网络隔离：只允许特定对象访问Pod（使用标签定义），允许白名单上的IP地址或者IP段访问Pod
- 基于Namespace级网络隔离：多个命名空间，A和B命名空间Pod完全隔离。

Pod网络出口方向隔离

- 拒绝某个Namespace上所有Pod访问外部
- 基于目的IP的网络隔离：只允许Pod访问白名单上的IP地址或者IP段
- 基于目标端口的网络隔离：只允许Pod访问白名单上的端口

### 2、网络策略概述

一个NetworkPolicy例子：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```

配置解析：

- podSelector：用于选择策略应用到的Pod组。

- policyTypes：其可以包括任一Ingress，Egress或两者。该policyTypes字段指示给定的策略用于Pod的入站流量、还是出站流量，或者两者都应用。如果未指定任何值，则默认值为Ingress，如果网络策略有出口规则，则设置egress。

- Ingress：from是可以访问的白名单，可以来自于IP段、命名空间、Pod标签等，ports是可以访问的端口。

- Egress：这个Pod组可以访问外部的IP段和端口。

### 3、入站、出站网络流量访问控制案例

**Pod访问限制**

准备测试环境，一个web pod，两个client pod

```
kubectl create deployment web --image=nginx
kubectl run client1 --generator=run-pod/v1 --image=busybox --command -- sleep 36000
kubectl run client2 --generator=run-pod/v1 --image=busybox --command -- sleep 36000
kubectl get pods --show-labels
```

需求：将default命名空间携带run=web标签的Pod隔离，只允许default命名空间携带run=client1标签的Pod访问80端口

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          project: default 
    - podSelector:
        matchLabels:
          run: client1
    ports:
    - protocol: TCP
      port: 80
```

隔离策略配置：

Pod对象：default命名空间携带run=web标签的Pod

允许访问端口：80

允许访问对象：default命名空间携带run=client1标签的Pod

拒绝访问对象：除允许访问对象外的所有对象

**命名空间隔离**

需求：default命名空间下所有pod可以互相访问，但不能访问其他命名空间Pod，其他命名空间也不能访问default命名空间Pod。

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-from-other-namespaces 
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
```

podSelector: {}：default命名空间下所有Pod

from.podSelector: {} : 如果未配置具体的规则，默认不允许




>讲师：李振良
>
>官方网站： http://www.ctnrs.com  
