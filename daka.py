#_*_ coding: utf-8 _*_
import os
import sys
import requests
import json
from bs4 import BeautifulSoup
from requests import sessions

#忽略警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

defaultencoding = 'utf-8'
if sys.getdefaultencoding() != defaultencoding:
    reload(sys)
    sys.setdefaultencoding(defaultencoding)

# 

import smtplib
from email.mime.text import MIMEText
from email.header import Header
 

def OnResult(ToAddr,error):
    myuser = ''         #发件邮箱
    mypass = ''         #授权码

    receivers = [ToAddr]  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱
    
    # 三个参数：第一个为文本内容，第二个 plain 设置文本格式，第三个 utf-8 设置编码
    message = MIMEText(error, 'plain', 'utf-8')
    message['From'] = Header('打卡通知', 'utf-8')   # 发送者
    message['To'] =  Header(ToAddr, 'utf-8')        # 接收者
    message['Subject'] = Header('本科生每日打卡', 'utf-8')
    
    try:
        smtpObj = smtplib.SMTP_SSL()
        smtpObj.connect(host='smtp.qq.com',port=465)
        smtpObj.login(myuser,mypass)
        smtpObj.sendmail(myuser, receivers, message.as_string())
        print("send email Ok")
    except smtplib.SMTPException:
        pass
    else:
        pass
#个人信息

Email = ''                      #通知邮箱,每次打卡结束后会往该邮箱发邮件
username = 'songbin2121'        #邮箱
password = ''                   #密码
MyName = ''
MyID   = ''             

#疫苗接种信息
YmjzCs = '2'
YmCj = '兰州生物'                       #疫苗厂商
YmJzdd = ''                             #疫苗接种地点.

#
schoolId = '1'
schoolName = '中心校区'

OrganizeID = "bks_100"                      #学院ID
OrganizeName = '计算机科学与技术学院'      #计算机科学与技术学院

#班级
MyClassId = "4218"                              #这些根据需求更改,得自己抓一下包看看post的是啥
MyClassName = '212107'                          #212107

#入学年纪
MyGradeId = "2021021"
MyGradeName = '2021'        #2021

#住宿信息
MyApartMentID = '10'
MyApartMentName = '南苑6公寓'
MyRoom = '119'

url = "https://ehall.jlu.edu.cn/infoplus/form/BKSMRDK/start"

'''
https://ehall.jlu.edu.cn/infoplus/form/BKSMRDK/start
↓
https://ehall.jlu.edu.cn/infoplus/login?retUrl=https%3A%2F%2Fehall.jlu.edu.cn%2Finfoplus%2Fform%2FBKSMRDK%2Fstart
↓
https://ehall.jlu.edu.cn/sso/oauth2/authorize?scope=openid&response_type=code&redirect_uri=https%3A%2F%2Fehall.jlu.edu.cn%2Finfoplus%2Flogin%3FretUrl%3Dhttps%253A%252F%252Fehall.jlu.edu.cn%252Finfoplus%252Fform%252FBKSMRDK%252Fstart&state=16e881&client_id=bwDBpMCWbid5RFcljQRP
↓
https://ehall.jlu.edu.cn/sso/login?x_started=true&redirect_uri=https%3A%2F%2Fehall.jlu.edu.cn%2Fsso%2Foauth2%2Fauthorize%3Fscope%3Dopenid%26response_type%3Dcode%26redirect_uri%3Dhttps%253A%252F%252Fehall.jlu.edu.cn%252Finfoplus%252Flogin%253FretUrl%253Dhttps%25253A%25252F%25252Fehall.jlu.edu.cn%25252Finfoplus%25252Fform%25252FBKSMRDK%25252Fstart%26state%3D16e881%26client_id%3DbwDBpMCWbid5RFcljQRP

pid 在最后一个html里面,post登录之后又会重定向到打卡页面,也就是最开始的https://ehall.jlu.edu.cn/infoplus/form/BKSMRDK/start


在html里面包含了js代码,执行 js post请求,获取entry_url 到达打卡页面

post https://ehall.jlu.edu.cn/infoplus/interface/render 获取已经填写的一些内容和供选择的内容

提交表单:

提交表单1
提交表单2

'''

headers = {
    'Host': 'ehall.jlu.edu.cn',
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
}

session = requests.Session()
response = session.get(url,headers=headers,verify=False)
refer = response.url

html = BeautifulSoup(response.text,features='html.parser')
tags = html.find_all('input')
pid = ''
for item in tags:
    name = ''
    try:
        name = item['name']
    except KeyError:
        pass
    else:
        if name == 'pid':
            pid = item['value']
            break
headers={
    'Host' :'ehall.jlu.edu.cn',
    "Referer":refer.encode("ascii"),
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://ehall.jlu.edu.cn",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
}
#print('refer:%s'%refer)
#print('pid:%s'%pid)
loginurl = "https://ehall.jlu.edu.cn/sso/login"
#登录请求
data = 'username=' + username + '&password='+ password +'&pid=' + pid + '&source='
data = data.encode('gbk')

print('username:%s'%(username))
print('password:%s'%(password))
print("logining....")
response = session.post(url=loginurl,data=data,headers=headers,cookies= session.cookies.get_dict(),verify=False)
#
if response.url != url:
    print("login failed!")
    OnResult(Email,'登录失败')
    exit(0)
#
print("login success!")
#
csrfToken = ''
html = BeautifulSoup(response.text,features='html.parser')
for item in html.find_all('meta'):
    try:
        if item['itemscope'] == "csrfToken":
            csrfToken =  item['content']
    except KeyError:
         pass
    else:
        pass
#跳转到开始页面后会执行里面的js代码跳转到 
data = 'idc=BKSMRDK&release=&csrfToken='
data += csrfToken
data +=  '&formData={"_VAR_URL":"https://ehall.jlu.edu.cn/infoplus/form/BKSMRDK/start","_VAR_URL_Attr":"{}"}'
#获取 entry_url
headers={
    'Host' :'ehall.jlu.edu.cn',
    "Referer":url,
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://ehall.jlu.edu.cn",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
}

interface=  'https://ehall.jlu.edu.cn/infoplus/interface/start'
response = session.post(url=interface,data=data,headers=headers,cookies= session.cookies.get_dict(),verify=False)
#输出信息.
res = json.loads(response.text)
if res['errno'] != 0:
    print('Error:%s'%res['error'])
    OnResult(Email,'打卡失败:%s'%res['error'])
    exit(0)


entry_url = res['entities'][0]
stepid = entry_url[len('https://ehall.jlu.edu.cn/infoplus/form/'):-7]

headers={
    'Host' :'ehall.jlu.edu.cn',
    "Referer":url,
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://ehall.jlu.edu.cn",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
}

#获取打卡页面
response = session.post(url=entry_url,headers=headers,cookies= session.cookies.get_dict(),verify=False)

csrfToken = ''
html = BeautifulSoup(response.text,features='html.parser')
for item in html.find_all('meta'):
    try:
        if item['itemscope'] == "csrfToken":
            csrfToken =  item['content']
            break
    except KeyError:
         pass
    else:
        pass

print('csrfToken : %s'%csrfToken)

#https://ehall.jlu.edu.cn/infoplus/interface/render
data = 'stepId=' + stepid +'&instanceId=&admin=false&rand=921.0620681636564&width=580&lang=zh&csrfToken=' + csrfToken
headers={
    'Host' :'ehall.jlu.edu.cn',
    "Referer":entry_url,
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://ehall.jlu.edu.cn",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 Edg/98.0.1108.62',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
}

#获取打卡详细信息.
response = session.post(url='https://ehall.jlu.edu.cn/infoplus/interface/render',data=data,headers=headers,cookies= session.cookies.get_dict(),verify=False)
#form 里面是提供的选择.下面没有使用到
form = json.loads(response.content)
#

#提交表单,手动填写内容
data = 'stepId=' + stepid + '&actionId=1&'
SubmitForm = {
     "_VAR_EXECUTE_INDEP_ORGANIZE_Name":OrganizeName,
    "_VAR_ACTION_ACCOUNT":MyID,
    "_VAR_ACTION_INDEP_ORGANIZES_Codes":OrganizeID,
    "_VAR_ACTION_REALNAME":MyName,
    "_VAR_ACTION_INDEP_ORGANIZES_Names":OrganizeName,
    "_VAR_OWNER_ACCOUNT":MyID,
    "_VAR_ACTION_ORGANIZES_Names":OrganizeName,
    "_VAR_STEP_CODE":"XSTX",
    "_VAR_ACTION_ORGANIZE":OrganizeID,
    "_VAR_OWNER_USERCODES":MyID,
    "_VAR_EXECUTE_ORGANIZE":OrganizeID,
    "_VAR_EXECUTE_ORGANIZES_Codes":OrganizeID,
    "_VAR_NOW_DAY":"4",
    "_VAR_ACTION_INDEP_ORGANIZE":OrganizeID,
    "_VAR_OWNER_REALNAME":MyName,
    "_VAR_ACTION_INDEP_ORGANIZE_Name":OrganizeName,
    "_VAR_NOW":"1646399026",
    "_VAR_ACTION_ORGANIZE_Name":OrganizeName,
    "_VAR_EXECUTE_ORGANIZES_Names":OrganizeName,
    "_VAR_OWNER_ORGANIZES_Codes":OrganizeID,
    "_VAR_ADDR":"49.140.54.202",
    "_VAR_URL_Attr":"{}",
    "_VAR_ENTRY_NUMBER":"85951412",         #流水号,随便改,改了之后不影响,这个没有被使用     
    "_VAR_EXECUTE_INDEP_ORGANIZES_Names":OrganizeName,
    "_VAR_STEP_NUMBER":"87449645",          
    "_VAR_POSITIONS":"bks_100:10002:21210710",
    "_VAR_OWNER_ORGANIZES_Names":OrganizeName,
    "_VAR_URL":"https://ehall.jlu.edu.cn/infoplus/form/87449645/render", 
    "_VAR_EXECUTE_ORGANIZE_Name":OrganizeName,
    "_VAR_EXECUTE_INDEP_ORGANIZES_Codes":OrganizeID,
    "_VAR_RELEASE":"true",
    "_VAR_EXECUTE_POSITIONS":"bks_100:10002:21210710",
    "_VAR_NOW_MONTH":"3",
    "_VAR_ACTION_USERCODES":MyID,
    "_VAR_ACTION_ORGANIZES_Codes":OrganizeID,
    "_VAR_EXECUTE_INDEP_ORGANIZE":OrganizeID,
    "_VAR_NOW_YEAR":"2022",
    
    #早打卡和晚打卡有区别
    "fieldXY2":"",
    "fieldWY":"1",                              
    "fieldXY1":"",                           
    
    "fieldFLid2":"1",
    "fieldDJXXyc":"1",
    "fieldSQrq":1646399026,                     #日期,应该是时间戳

    "fieldDJXX":"https://ehall.jlu.edu.cn/jlu_meet_new/student_partyteachers#sfty=1",      #学 <习>?#sfty=1 不清楚
    "fieldSQxm":MyID,                          #姓名ID 
    "fieldSQxm_Name":MyName,                   #姓名
    "fieldXH":MyID,                            #学号
    "fieldSQxy":OrganizeID,                    #学院ID
    "fieldSQxy_Name":OrganizeName,             #学院名称

    "fieldSQnj":MyGradeId,                     #年级ID
    "fieldSQnj_Name":MyGradeName,              #年纪名称 入学时间 2021,这个会显示.
    "fieldSQnj_Attr":"{\"_parent\":\"bks_100\"}",
    "fieldSQbj":MyClassId,                     #班级ID
    "fieldSQbj_Name":MyClassName,              #班级名称
    "fieldSQbj_Attr":"{\"_parent\":\"2021021\"}",
    "fieldSQxq":schoolId,                       #校区ID
    "fieldSQxq_Name":schoolName,                #校区名称
    "fieldSQgyl":MyApartMentID,                 #公寓ID
    "fieldSQgyl_Name":MyApartMentName,          #公寓名称
    "fieldSQgyl_Attr":"{\"_parent\":\"1\"}",
    "fieldSQqsh":MyRoom,                        #寝室号
    "fieldHidden":"",
    "fieldSheng":"",                            #省 编号
    "fieldSheng_Name":"",                       #省 Name
    "fieldShi":"",                              #市 编号
    "fieldShi_Name":"",                         #市 Name
    "fieldShi_Attr":"{\"_parent\":\"\"}",
    "fieldQu":"",                               #区 编号
    "fieldQu_Name":"",                          #区 Name
    "fieldQu_Attr":"{\"_parent\":\"\"}",
    "fieldQums":"",
    "fieldJBXXsfjzym":"1",                      #是否接种疫苗
    "fieldJBXXsfjzymcs":YmjzCs,                 #接种次数
    "fieldJBXXsfjzymsj":1631203200,             #接种时间
    "fieldJBXXsfjzymcj":YmCj,                   #疫苗厂家
    "fieldJBXXsfjzymjzddz":YmJzdd,              #疫苗接种地点
    
    "fieldZtw":"1",                             #早打卡,1 正常
    "fieldZtwyc":"",
    "fieldZhongtw":"",
    "fieldZhongtwyc":"",

    "fieldWantw":"",
    "fieldWantwyc":"",
    "fieldHide":"",
    "fieldXY3":"",                              #晚签到,早签到
    "_VAR_ENTRY_NAME":"本科生每日健康打卡",      #来源 本科生每日健康打卡
    "_VAR_ENTRY_TAGS":"学生工作部"          
}

print("Submit Form")
data += 'formData=' + json.dumps(SubmitForm) + '&'
data += 'timestamp=1646399025&rand=870.6183822323169&'
data += 'boundFields=fieldXH,fieldZtw,fieldHidden,fieldJBXXsfjzymcs,fieldSQqsh,fieldSQbj,fieldSQgyl,fieldJBXXsfjzymcj,fieldQums,fieldQu,fieldFLid2,fieldJBXXsfjzymsj,fieldDJXX,fieldSQxm,fieldWantw,fieldJBXXsfjzymjzddz,fieldSQxy,fieldWY,fieldXY1,fieldZtwyc,fieldXY2,fieldDJXXyc,fieldXY3,fieldZhongtw,fieldSQxq,fieldShi,fieldWantwyc,fieldJBXXsfjzym,fieldSQnj,fieldSheng,fieldZhongtwyc,fieldHide,fieldSQrq&'
data += 'csrfToken=' + csrfToken + '&lang=zh'
data = data.encode('utf-8')
#step1
response = session.post(url='https://ehall.jlu.edu.cn/infoplus/interface/listNextStepsUsers',data=data,headers=headers,cookies=session.cookies.get_dict(),verify=False)

#step2, do action
#https://ehall.jlu.edu.cn/infoplus/interface/doAction

data += b'remark=&'
data += b'nextUsers={}&'

response = session.post(url='https://ehall.jlu.edu.cn/infoplus/interface/doAction',data=data,headers=headers,cookies=session.cookies.get_dict(),verify=False)

result = json.loads(response.text)

if result['errno'] == 0:
    print("Success!")
    OnResult(Email,'打卡成功')
else:
    print("打卡失败: %s!\n请手动打卡!"%result['error'])
    OnResult(Email,"打卡失败: %s!"%result['error'])
