# MiniFTP / FTP服务器
## 开发语言
C/C++
## 开发环境
CentOS7、LeapFTP、vim、gcc、gdb、git、MakeFile
## 项目介绍
MiniFTP是一个FTP服务器软件，通过使用MiniFTP能够快速的将任何一台PC设置成为一个简易的FTP服务器，
任何一台PC都可以通过使用FTP协议来与服务器进行连接，进行文件的访问、存储、管理等，实现信息共享的功能。
## 项目特点
- 实现FTP命令如：USER、PASS、PORT、PASV、TYPE、LIST、SYST、FEAT、PWD、SIZE、CWD、RNFR/RNTO、STOR、RETR、MKD、RMD、CWD、QUIT、DELE、REST、CDUP
- 具有用户鉴权登录、断点续传（续载）、传输限速、配置文件解析等功能
- 实现主动和被动两种连接模式，通过nobody进程协助ftp服务进程创建数据连接与特权端口绑定。
- 实现控制连接和数据连接的空闲断开，缓解了服务器的压力。
- 通过哈希表实现最大连接数、每ip连接数的限制，防止大量的恶意访问。
