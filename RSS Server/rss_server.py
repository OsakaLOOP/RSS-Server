import socketserver
import http.server
import requests

import threading
import random
import time
import sys
import unicodedata
import urllib

import smtplib
import sqlite3

from github import Github, Auth, UnknownObjectException
#from octokit import Octokit



# 利用 OAuth 实现自主登陆 Github , 检测 Commit, 分类汇聚, 生成 RSS xml, 最后由 nginx 分发
# OAuth api 速率限制: 10/h, max 1/5s

# Step0 - 培养强迫症: 请按 Conventional Commits (*有变动)提交对应 repo 下的 commit !


'''提交说明的结构

提交说明的结构如下所示：

<类型>([可选的作用域]): <描述>

[可选的正文]
[可选的脚注]
复制
类型(type)

feat: 新增功能(对应语义化版本中的 MINOR)。

fxed: 修复缺陷(对应语义化版本中的 PATCH)。

docs: 文档更新。

styl: 风格更改，不影响逻辑。

rfct: 重构代码。
'''

# Step1 - 登陆
# 生成用户链接, 通过浏览器向 Github 发送 GET 并授权, 经含 code 的 Redirect URI 重定向到 localhost, 得到 code
# 再用 code 向 Github 发送 POST 获取 Auth 并保存

# Step2 - 发现 user, repo, 监测 Commit, Command Line 输出

# ---------- 以下尚未实现 ----------

# Step3 - 指定位置生成 RSS xml 文件

# Step4 - e-mail 推送 api 



class OAuthCallBackHandler(http.server.SimpleHTTPRequestHandler):
    #Server
    def do_GET(self):
        global oauth_result
        global res_error
        
        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path=='/auth':
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            if 'code' in query_params and 'state' in query_params:
                oauth_result["code"] = query_params['code'][0]
                oauth_result["state"] = query_params['state'][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write('<html><meta charset="UTF-8"><body><title>RSS Server - 授权成功</title><h1>授权成功！</h1><p>Code 已被本地应用捕获。您可以关闭此页面。</p></body></html>'.encode())
                
            elif 'error' in query_params:
                res_error=query_params.get('error_description',['Unknown error'])
                self.send_response(400)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f'<html><body><title>RSS Server - 授权失败</title><h1>授权失败！</h1><p>错误: {res_error}</p></body></html>'.encode())
            
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 Not Found")
                print('收到未知请求:',str(query_params))
        
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            print('收到未知请求:',self.translate_path(self.path))
            
def runCallbackServer():
    with socketserver.TCPServer((ADDR, PORT), OAuthCallBackHandler, bind_and_activate=False) as httpd:
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        print(f'本地服务器启动，监听于 {ADDR}:{PORT}...')
        
        global http_server_instance
        http_server_instance = httpd
        
        httpd.serve_forever()
        
def genUserURI():
    global State
    State = StateBase+str(random.randint(0,1000))
    BaseURL = 'https://github.com/login/oauth/authorize/'
    query_params = {
        'client_id': CliID,
        'redirect_uri': RedirURI,
        'state': State,
        'scope': Scope, 
        'allow_signup': 'true'
    }
    query_str = urllib.parse.urlencode(query_params)
    UserURI = f'{BaseURL}?{query_str}'
    return UserURI

def getAuth():
    print('请打开链接授权Auth')
    print(genUserURI())
    start_time = time.time()
    if not server_thread.is_alive():
             sys.exit("服务器启动失败，请检查端口是否被占用。")
    while (oauth_result['code'] is None and res_error == [] and time.time()-start_time <= max_wait):
        time.sleep(0.1)
    if 'http_server_instance' in globals():
        print(f'\n本地服务器停止, 用时 {time.time()-start_time}s')
        if oauth_result["code"] and oauth_result['state'] == State:
            print("成功捕获 OAuth Code, 验证 State 安全！")
            return([oauth_result["code"],oauth_result["state"]])
        elif oauth_result['state'] != State:
            print("警告: State 验证失败！可能存在 CSRF 攻击！")
            return(['State Error',oauth_result['state']])
        else:
            return(['Parse Error',oauth_result['state']])
    if time.time()-start_time<=max_wait:
        print('超时:',max_wait)
        return(['Time Out'])
        
def getToken():
    
    global ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_EXPIRATION, REFRESH_TOKEN_EXPIRATION
    
    token_url = 'https://github.com/login/oauth/access_token'
    payload = {
        'client_id': CliID,
        'client_secret': CliSEC,
        'code': result[0],
        'redirect_uri': RedirURI,
    }
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.post(token_url, data=payload, headers=headers)
        response.raise_for_status()
        
        token_data = response.json()
        
        if 'access_token' in token_data:
            # 捕获所有新的和必需的参数
            ACCESS_TOKEN = token_data['access_token']
            REFRESH_TOKEN = token_data.get('refresh_token') 
            TOKEN_EXPIRATION = token_data.get('expires_in') 
            REFRESH_TOKEN_EXPIRATION = token_data.get('refresh_token_expires_in')
            
            token_type = token_data.get('token_type', 'bearer')
            token_scope = token_data.get('scope') if token_data.get('scope')!='' else 'N/A'
            
            print("成功获取 Access Token!\n"+'Auth 结果 - Token: '+ACCESS_TOKEN)
            print(f"Token 类型: {token_type}, 范围: {token_scope}")
            if TOKEN_EXPIRATION:
                print(f"Token 有效期: {TOKEN_EXPIRATION} 秒")
            else:
                print('Token 无有效期')
            if REFRESH_TOKEN:
                 print(f"Refresh Token 有效期: {REFRESH_TOKEN_EXPIRATION} 秒")
            else:
                print('无 Refresh Token')
                 
            return ACCESS_TOKEN
        elif 'error' in token_data:
            print(f"令牌交换失败: {token_data.get('error')}")
            print(f"描述: {token_data.get('error_description')}")
            return None
        else:
            print("令牌交换响应格式异常。")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"POST 请求失败: {e}")
        return None

def rewriteToken():
    #To be continued
    global token_storage
    token_storage = UserToken
    cur.execute('''   
                INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)
                ''', ('token_storage', token_storage))  
    db.commit()

def messageSubtype(msg):
    try: 
        return(msg.split(sep='[')[1].split(sep=']')[0]).strip()
    except:
        try:
            return(msg.split(sep=':'))[0].strip()
        except:
            return(msg)

def messageContent(msg):
    try:
        return(msg.split(sep=':')[1]).strip()
    except:
            return(msg)

def classifyCommits(message: str) -> str:
    message_l = message.lower().strip()
    
    if message_l[:4]=="feat":
        return f"Feature - {messageSubtype(message_l)}"
    elif message_l[:4]=="fxed":
        return f"Bug Fix - {messageSubtype(message_l)}"
    elif message_l[:4]=="docs":
        return f"Documentation - {messageSubtype(message_l)}(文档内容更新)"
    elif message_l[:4]=="styl":
        return f"Style - {messageSubtype(message_l)} (前端样式优化)"
    elif message_l[:4]=="rfac":
        return f"Refactor - {messageSubtype(message_l)}"
    elif message_l[:4]=="test":
        return f"Test - {messageSubtype(message_l)}"
    else:
        return f"Other - {messageSubtype(message_l)}"

def printCommit(cmt):
    message = cmt.commit.message.split('\n')
    category = classifyCommits(message[0])
    date_time = cmt.commit.author.date.strftime('%Y-%m-%d %H:%M:%S')
    author = cmt.commit.author.name
    prtLst=[(20,'['+category+']','beg'),(20, date_time,'mid'),(15, author,'mid'),(8,cmt.sha[:8],'mid'),(0,'//'.join(message),'end')]
    exactPrt(prtLst)
    #print(f"{('['+category+']'):<20} {date_time:>20} | {author:^15} | {cmt.sha[:8]} | {'//'.join(message)}") # Seperate multiple lines

def exactLen(tot:int,strIn:str)->int:
    len0=len(strIn)
    len1=0
    for x in strIn:
        if unicodedata.east_asian_width(x) in 'FWA':
            len1 += 2
        else:
            len1 += 1
    return tot-(len1-len0)
# calc display len of str to exactly align multiple lines

def exactPrt(lst:list):
    for i in lst:
        if i[2] in [0, 'beg']:
            print(f'{i[1]:<{exactLen(i[0],i[1])}}',end='   ')
        elif i[2] in [1, 'beg-title']:
            print(f'{i[1]:^{exactLen(i[0],i[1])}}',end='   ')    
        elif i[2] in [2, 'mid']:
            print(f'{i[1]:^{exactLen(i[0],i[1])}}',end=' | ')
        elif i[2] in [3, 'end']:
            print(i[1],end='')
        elif i[2] in [4,'end-title']:
            print(f'    {i[1]}',end='')
    print('\n',end='')
    

def monitoring(g:Github, RepoNme:str, BranchNme:str, interval:int):
    
    print(f'开始监控 - Repo[{RepoNme}] Branch[{BranchNme}] 间隔: {interval}s\n按 Ctrl+C 停止')
    tarRepo=None
    tarBranch=None
    
    try:
        tarRepo = g.get_repo(RepoNme)
        tarBranch = tarRepo.get_branch(BranchNme)
    except UnknownObjectException:
        print(f'错误: Repo {RepoNme} 无访问权限')
        return
    except Exception as e:
        print(f'错误: {e}')
        
    lastSHA=None
    
    while True:
        try:
            # 获取目标分支的最新提交
            currentCommit=tarBranch.commit
            currentSHA = currentCommit.sha
            titleLst=[(20,'Commit 类型','beg-title'),(20,'时间戳','mid'),(15,'作者','mid'),(8,'SHA8','mid'),(0,'描述','end-title')]

            if lastSHA is None:
                # 首次运行，只记录最新的 SHA，不处理旧提交
                print(f"首次检查：当前最新提交 SHA 为 {currentSHA[:8]}")
                exactPrt(titleLst)
                # will def a seperate function
                printCommit(currentCommit)
                
            elif currentSHA != lastSHA:
                print(f"检测到新提交！")
                
                # 获取从 last_sha 到 current_sha 之间的所有新提交
                newCommits = []
                for cmt in tarRepo.get_commits(sha=BranchNme):
                    if cmt.sha == lastSHA:
                        break
                    
                    newCommits.append(cmt)
                    
                    if len(newCommits) > 20: 
                        break
                    time.sleep(0.1)

                # 从旧到新打印新提交
                for cmt in reversed(newCommits):
                    printCommit(cmt)
            
            lastSHA = currentSHA
        
        except UnknownObjectException:
            print(f"错误：分支 '{BranchNme}' 不存在")
            break
        except requests.exceptions.RequestException as e:
            print(f"API 请求失败: {e}")
        except Exception as e:
            print(f"意外错误: {e}")
    
        # 等待下一个轮询周期
        time.sleep(interval)

    
    
    
#def readHistory():
    
#def makeRSS():



if __name__=='__main__':
    db = sqlite3.connect('data.db')
    cur = db.cursor()
    dbRes = cur.execute("SELECT name FROM sqlite_master")
    nameLst = [nme[0] for nme in dbRes.fetchall()]
    if 'config' in nameLst and 'commit_log'in nameLst:
        print('已连接到现有数据库')
    else:
        print('初始化数据库')
        try:
            if not 'config' in nameLst:
                cur.execute('''CREATE TABLE config (
                                key TEXT PRIMARY KEY,
                                value TEXT
                            )''')
            if not 'commit_log' in nameLst:
                cur.execute('''CREATE TABLE commit_log (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                message TEXT,
                                author TEXT,
                                date TEXT NOT NULL,
                                sha TEXT
                            )''')
            db.commit()
        except Exception as e:
            print(f'数据库初始化失败: {str(e)}')
        
    # Init config
    config={}
    configFallback={'ADDR':'127.0.0.1','PORT':8964,'max_wait':30,'CliID':'censored','CliSEC':'censored','UserName':'OsakaLOOP','RepoName':'OsakaLOOP/censored','BranchName':'main','RedirURI':'http://127.0.0.1:8964/auth','Scope':'repo','StateBase':'censored','token_storage':'gho_censored'}
    # replace the censored content for your own. see more on RESET api wiki
    # If your repo is private, than that's it; otherwise, use 'user'
    # Change above for your Github Client/Repo
    
    try:
        for k in configFallback.keys():
            cur.execute('''
                        INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)
                        ''', (k, configFallback[k]))
            db.commit()
        cur.execute('SELECT key, value FROM config')
        rows = cur.fetchall()
        for row in rows:
            config[row[0]] = row[1]
        
        ADDR=config['ADDR']
        PORT=int(config['PORT'])
        max_wait=int(config['max_wait'])
        CliID=config['CliID']
        CliSEC=config['CliSEC']
        UserName=config['UserName']
        RepoName=config['RepoName']
        BranchName=config['BranchName']
        RedirURI=config['RedirURI']
        Scope=config['Scope']
        StateBase=config['StateBase']
        token_storage=config['token_storage']
        
    except Exception as e:
            print(f'配置初始化失败: {str(e)}')
    


    AuthURI=urllib.parse.quote(RedirURI)
    # URI standard safe

    #StateBase='zundamon0721'    # State will be attached with a dynamic 4-digit suffix for safety

    #token_storage='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'   # Hard-wired fallback

    oauth_result={'code':None,'state':None}
    res_error=[]
    if token_storage!='':
        Decision=True if input('请确认是否利用现存 Token: '+token_storage+' 若是请输入T\n')=='T' else False
        if Decision:
            UserToken=token_storage
        else:
            server_thread=threading.Thread(target=runCallbackServer, daemon=True)
            server_thread.start()
            result=['Not Yet']
            while result[0] in ['Not Yet', 'Parse Error','State Error','Time Out']:  
                result=getAuth()
                print('Auth 结果 - ', 'Code:', result[0], 'State:',result[1])
            if http_server_instance:
                http_server_instance.shutdown()
                server_thread.join()
            if result[0]!='Not Yet':
                UserToken=getToken()
            if UserToken!=token_storage:
                rewriteToken()

    if UserToken:
        auth=Auth.Token(UserToken)
        g=Github(auth=auth)
        user=g.get_user()
        repoDict={}
        repos=user.get_repos()
        exc=False
        try:
            for i in repos:
                repoDict[i.name]=i
        
            print('获取用户名:',user.login if user.login else'N/A',end='')
            print(' - 确认匹配' if user.login==UserName else ' - 不匹配!应为'+UserName)
            print('获取 Repos:',list(repoDict.keys()),' - 查找到对应 Repo' if RepoName.split('/')[1] in repoDict.keys() else '不存在对应 Repo:'+ RepoName.split('/')[1]) 
            monitoring_thread=threading.Thread(target=monitoring ,args=(g, RepoName, BranchName, 60),daemon=True)
            monitoring_thread.start()
            
        except Exception as e:
            print(f'错误: GFW 坏事做尽, 请检查 VPN 是否连接 - {str(e)[:10]}')
            exc = True
            
        while True and not exc:
            time.sleep(1)
            
        db.close()
        print('已终止')