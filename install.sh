#!/bin/bash
#此sh为配置环境变量
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
CatGames_LoGo
echo "============================================================"
if [ -f "./CatGames1.4.sh" ];then
echo "CatGames Attack EXP Now run"
else
echo "[-]Catgames attack exp file does not exist or has an exception. Please check whether install.sh and catgames1.4.sh are in the same directory.
[-]If not, please put them in the same directory and run. / install.sh
[-]if you cannot solve this problem,"
read -p "[+]Now git clone https://github.com/CatGamesGa0/CatGamesAuToExP.git Please enter yes or enter to exit：" Git
  if [ $Git ]; then
      git clone https://github.com/CatGamesGa0/CatGamesAuToExP.git
  fi
 exit
fi
sleep 1
echo "=========================================================="
mv ./CatGames1.4.sh /usr/bin/CatGamesexp
echo "[+]Catgames1.4 has been moved to /usr/bin/CatGamesexp"
echo "=========================================================="
sleep 1
echo "=========================================================="
dos2unix /usr/bin/CatGamesexp
chmod 777 /usr/bin/CatGamesexp
echo "=========================================================="
sleep 1
echo "[+]Now you can input CatGamesexp in the terminal to start the program, or enter C and press tab to make up automatically. Please pay attention to the case"
echo "[+]现在可以在终端输入CatGamesexp即可启动程序，或者输入C并且按下Tab也会自动补齐，请注意大小写"
echo "[+]Good luck Have a good time"
