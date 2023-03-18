  <div align="center">
 <img src="https://readme-typing-svg.herokuapp.com/?lines=This_is_a_safe_tool_You_can_use_it_safely.;---@Мартин.&font=Roboto" />
 <p align="center">
 <img title="MDOG_GGB" src='https://img.shields.io/badge/MDOG_GGB-3.6.4-brightgreen.svg' />
 <img title="MDOG_GGB" src='https://img.shields.io/badge/XSS-Tool'/>
 <img title="MDOG_GGB" src='https://img.shields.io/badge/Python-3.9-yellow.svg' />
  <img title="MDOG_GGB" src='https://img.shields.io/badge/HackerTool-x' />
 <img title="MDOG_GGB" src='https://img.shields.io/static/v1?label=Author&message=@Martin&color=red'/>
 <img title="MDOG_GGB" src='https://img.shields.io/badge/-Linux-F16061?logo=linux&logoColor=000'/>
 </p>
  
  <a href="https://www.murphysec.com/accept?code=7851aba9e54808485ea75df92e7a14bf&type=1&from=2&t=2" alt="Security Status"><img src="https://www.murphysec.com/platform3/v3/badge/1613745874211995648.svg?t=1" /></a>
  
  <img height="137px" src="https://github-readme-stats.vercel.app/api?username=MartinXMax&hide_title=true&hide_border=true&show_icons=trueline_height=21&text_color=000&icon_color=000&bg_color=0,ea6161,ffc64d,fffc4d,52fa5a&theme=graywhite" />
  
   
 <table>
  <tr>
      <th>Function</th>
  </tr>
  <tr>
    <th>Obtain the victim's public IP address(Update logging)</th>
  </tr>
  <tr>
    <th>Get administrator cookies(Update logging)</th>
  </tr>
  <tr>
    <th>Page Redirection(Update logging)</th>
  </tr>
  <tr>
    <th>Host data sharing(Update logging)</th>
  </tr>

  <tr>
    <th>DingTalk data sharing</th>
  </tr>
  <tr>
    <th>Remote phishing page deployment(Update logging)</th>
  </tr>
 </table>
</div>

## usage method
  * View help information

      ```#python3 MDOG.py -h```

  ![图片名称](./Demo_image/MG1.png)  

# Advanced attack
* Cookie theft (There are no cookies here) and remote deployment of phishing pages

1.Target Web

  ![图片名称](./Demo_image/MG2.png) 

2.Fill in parameters for remote deployment phishing page

(Linux will act as the shared data party, and win will act as the shared data party and push the data)

```python3 %s -t -rbtcp (Ngrok TCP Tunnel)  -rwtcp (Ngrok TCP Tunnel) -rs -wf fs.html -table -button BT -user UA -pass PA```

![图片名称](./Demo_image/MG3.png) 

3.Inject Code

![图片名称](./Demo_image/MG4.png) 

4.When anyone visits this page, the cookies and public IP will be disclosed

Win

![图片名称](./Demo_image/MG5.png) 

Linux

![图片名称](./Demo_image/MG6.png) 

First, we will get the basic information, and then wait for the victim to enter the account password, because the URL of the other party has not changed, which can greatly improve the probability of successful phishing

![图片名称](./Demo_image/MG7.png) 


