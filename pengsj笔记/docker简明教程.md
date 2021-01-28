---
typora-copy-images-to: ./images
typora-root-url: ../md学习文件
---

# docker容器

## 在容器内运行一个应用程序

`docker run 镜像 命令`

## 交互式的容器

`docker run -ti 镜像 /bin/bash`

## 后台运行容器

`docker run -d 镜像 命令`

上面的命令会返回容器的ID

## 端口映射

`docker run -P`

将容器内部使用的网络端口映射到我们使用的主机上

-p 端口号：端口号

## 查看运行的容器

`docker ps -a`

## 查看容器内的标准输出

`docker logs 容器ID`

## 停止容器

`docker stop 容器ID/容器名`

## 启动一个停止的容器

`docker start 容器ID/容器名`

`docker restart 容器ID/容器名`

## 进入容器

进入在后台运行的容器

`docker attach  `

如果这个容器退出，会导致容器的停止

`docker exec`

但是上面这个命令如果容器退出，容器不会停止。

## 导出容器

`docker export 容器ID > 命名.tar`

## 导入容器快照

`cat docker/ubuntu.tar | docker import - test/ubuntu:v1`

这个时候的导入为镜像文件

## 删除容器

`docker rm -f 容器ID`

## 清理掉所有处于终止状态的容器

`docker container prune`

## 查看容器内部运行的进程

`docker top 容器名`

## 查看容器的配置和状态信息

`docker inspect 容器名`

# docker镜像

## 删除镜像

`docker rmi`

## 查找镜像

`docker search`

## 拉取镜像

`docker pull`

## 创建镜像

- 方法1 ：

从已经创建的容器中更新镜像，并且提交这个镜像

- 方法2 ：

使用*Dockerfile*指令创建一个新的镜像

### 更新镜像

首先使用镜像来创建一个容器：

`docker run -ti 镜像 命令（/bin/bash`

在运行的容器内使用命令进行更新。

提交容器副本：

`docker commit -m="has update" -a="runoob" 容器ID runoob/ubuntu：v2`

*-m*：提交的描述信息

*-a*：指定镜像作者

最后面的参数是指定要创建的目标镜像名

### 构建镜像

使用命令`docker build`，从零创建一个新的镜像。为此，我们需要创建一个*Dockerfile*文件，其中包含一组指令告诉docker怎么创建自己的镜像。

`cat Dockerfile`

每个指令都会在镜像上创建一个新的层，每一个指令的前缀都必须是大写的。

**FROM** 指定使用哪个镜像源

**RUN** 告诉docker在镜像内执行命令，安装了什么

然后使用`docker build`创建一个镜像

`docker build -t runoob/centos:6.7 .`

*-t*：指定要创建的目标镜像名

*.*：*Dockerfile*文件所在目录，可以指定*Dockerfile*的绝对路径

## 设置镜像标签

`docker tag 容器ID 用户名/镜像名：新的标签名`

## Dockerfile

**RUN**:命令行命令

#等同于在终端操作的shell命令

注：Docker的指令每执行一次都会在docker上新建一层。所以过多无意义的层，会造成镜像膨胀过大。

**COPY**：复制指令，从上下文目录中复制文件到容器里指定路径。

**ADD**：与**COPY**使用格式一样

**CMD**：在`docker run`时运行，为启动的容器指定默认要运行的程序，程序运行结束，容器也就结束。**CMD**指令指定的程序可被`docker run`命令参数中指定要运行的程序所覆盖。

**ENTRYPOINT**：类似于**CMD**指令，但其不会被`docker run`的命令行参数指定的指令覆盖。搭配**CMD**使用，一般是变参才会使用**CMD**，这里的**CMD**等于是在给**ENTRYPOINT**传参。

![image-20210125213030235](\images\image-20210125213030235.png)

**ENV**：设置环境变量，定义了环境变量，那么在后续的指令中，就可以使用这个环境变量。

**WORKDIR**：指定工作目录。指定的工作目录会在构建镜像的每一层中都存在。并且指定的工作目录必须是提前创建好的。

# docker compose

*Compose*是用于定义和运行多容器Docker应用程序的工具。通过compose，可以使用yml文件来配置应用程序需要的所有服务。然后，使用一个命令，就可以从yml文件配置中创建并启动所有服务。

compose使用的三个步骤：

1. 使用*Dockerfile*定义应用程序的环境。

2. 使用*docker-compose.yml*定义构成应用程序的服务，这样他们可以在隔离环境中一起运行。
3. 最后，执行`docker-compose up`命令来启动并运行整个应用程序。

# docker 代理

- 创建文件夹：

`mkdir -p /etc/systemd/system/docker.service.d`

- 在*docker.service.d*文件夹下创建*http_proxy.conf*文件：

`touch http_proxy.conf`

- 编辑该文件`vi http_proxy.conf`

```shell
 [Service]

  Environment="HTTP_PROXY=http://172.18.217.160:1282/"    

  Environment="HTTPS_PROXY=http://172.18.217.160:1282/"  

  Environment="NO_PROXY=localhost,127.0.0.0/8,docker-registry.somecorporation.com"
```

上面的网址可修改为任意一台可翻墙的主机的地址和端口号。

- 重启docker服务

  `systemctl daemon-reload`

  `systemctl restart docker`

  

