import os

import pytesseract
import requests
import execjs
from PIL import Image, ImageFilter
import re
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from datetime import datetime, timedelta
import json


class AesCbcZeroPadding(object):
    """
    AES CBC zeropadding
    结果呈现 hex， 中途使用 utf-8 编码
    """

    # 如果text不足16位的倍数就用空格补足为16位
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def add_to_16(self, text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    # 加密函数
    def encrypt(self, text):
        key = self.key.encode('utf-8')
        mode = AES.MODE_CBC
        iv = bytes(self.iv.encode('utf-8'))
        text = self.add_to_16(text)
        cryptos = AES.new(key, mode, iv)
        cipher_text = cryptos.encrypt(text)
        # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
        return b2a_hex(cipher_text)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        key = self.key.encode('utf-8')
        iv = bytes(self.iv.encode('utf-8'))
        mode = AES.MODE_CBC
        cryptos = AES.new(key, mode, iv)
        plain_text = cryptos.decrypt(a2b_hex(text))
        return bytes.decode(plain_text).rstrip('\0')


class OutSchool(object):
    username = None
    password = None
    head = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36 Edg/86.0.622.38',
    }
    cookie = None
    session = None

    def __init__(self, username, password):
        self.session = requests.session()
        self.session.headers = self.head
        self.username = username
        self.password = password

    # 需要搞定图像识别，得到验证码
    def getCode(self):
        # 需要获取验证码
        codeUrl = "https://pass.hust.edu.cn/cas/code"
        r = self.session.get(codeUrl)
        path = "./image/code.gif"
        with open(path, "wb") as file:
            file.write(r.content)

        image = Image.open(path)
        try:
            while True:
                s = image.tell()
                image.save(path[:-4] + str(s) + '.png')
                image.seek(s + 1)
        except EOFError:
            pass

        # 第一张和第四张
        # 0 17 37 40
        image3 = Image.open(path[:-4] + '3' + '.png').crop((0, 16, 38, 40))
        # w: 37 h: 23
        image0 = Image.open(path[:-4] + '0' + '.png').crop((44, 16, 82, 40))
        image = Image.new("RGB", (image3.size[0] * 2, image3.size[1]))
        image.paste(image3, (0, 0))
        image.paste(image0, (image3.size[0], 0))
        image = image.convert('L')
        image.save(path[:-4] + 'gray.png')
        # 黑色是 0， 白色是 1
        threshold = 200
        table = []
        for i in range(256):
            if i < threshold:
                table.append(0)
            else:
                table.append(1)
        image = image.point(table, '1')
        image.save(path[:-4] + '111.png')
        image = image.filter(ImageFilter.ModeFilter(2))
        image.save(path[:-4] + '111_mode.png')

        # code = input('请输入验证码：')
        # return code
        code = pytesseract.image_to_string(image, config="--psm 7")
        # 替换非数字部分
        code = re.sub(r'[^\d]', '', code)
        return code

    def login(self, url):
        # self.session.headers = self.head
        response = self.session.get(url)
        html = response.text

        code = self.getCode()
        # code = input('请输入验证码：')
        print(code)
        if len(code) != 4:
            return False

        lt = re.search('id="lt" name="lt" value="(.*?)"', html).group(1)
        action = re.search('id="loginForm" action="(.*?)"', html).group(1)

        with open('des.js') as file:
            comp = execjs.compile(file.read())
        s = self.username + self.password + lt
        rsa = comp.call('strEnc', s, '1', '2', '3')

        # code = 1234
        loginData = {
            'code': code,
            'rsa': rsa,
            'ul': len(self.username),
            'pl': len(self.password),
            'lt': lt,
            'execution': 'e1s1',
            '_eventId': 'submit'
        }
        post_url = 'https://pass.hust.edu.cn' + action
        r = self.session.post(post_url, data=loginData)
        if re.search(r'连续登录失败5次，账号将被锁定1分钟，剩余次数', r.text) is not None or re.search(r'抱歉！您的请求出现了异常，请稍后再试。', r.text) is not None:
            return False
        return True

    def getProfile(self):
        # 获取个人信息，主要获取学院id和学院名字
        url = 'http://one.hust.edu.cn/dcp/profile/profile.action'
        data = {
            "map": {
                "method": "getInfo",
                "params": None
            },
            "javaClass": "java.util.HashMap"
        }
        head = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "clientType": "json",
            "Connection": "keep-alive",
            "Content-Type": "text/plain;charset=UTF-8",
            "render": "json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.54"
        }
        home_url = "http://one.hust.edu.cn/dcp/forward.action?path=/portal/portal&p=home"
        session = self.session
        session.get(home_url)
        r = session.post(url, json=data, headers=head)
        try:
            return {
                "deptName": re.search(r'"UNIT_ID":"(.*?)"', r.text).group(1),
                "deptNo": re.search(r'"UNIT_NAME":"(.*?)"', r.text).group(1)
            }
        except:
            return None

    def dateOutSchool(self, config, dept):
        # 预约出校的函数，需要先发一次 get ，得到 cookie，使用 session 保存
        url = 'http://access.hust.edu.cn/IDKJ-P/P/studentApi'
        r = self.session.get(url, headers=self.head)

        # 对如下json加密，加密之后填到上面的data，然后直接post就行
        f_form_data = {"applyUserName": config['USERNAME'], "applyUserId": config['USER_ID'], "schoolArea": "0000",
                       "bookingUserIDcard": config['USER_ID_CARD'], "deptName": dept['deptName'],
                       "deptNo": dept['deptNo'], "bookingStartTime": "2022-08-27 23:13:46",
                       "bookingEndTime": "2021-12-15 23:13:46", "visitCase": "11111111"}
        # 修改一下时间，修改为当前时间，和一天之后的时间
        startTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        endTime = (datetime.strptime(startTime, '%Y-%m-%d %H:%M:%S') + timedelta(1)).strftime(
            '%Y-%m-%d %H:%M:%S')
        print(startTime)
        print(endTime)
        f_form_data['bookingStartTime'] = startTime
        f_form_data['bookingEndTime'] = endTime

        # 对数据进行加密
        aes = AesCbcZeroPadding('123456789ABCDEFG', '123456789ABCDEFG')
        f_str_data = json.dumps(f_form_data, ensure_ascii=False, separators=(',', ':'))
        # 注意需要转化数据格式
        en_data = aes.encrypt(f_str_data).decode('utf-8')
        data = {
            "parkId": "42011112000021",
            "sign": "4A58DA6D2EFF82BD438915280254C513",
            "timeStamp": "2019-04-30 10:57:32",
            "data": en_data
        }
        postUrl = 'http://access.hust.edu.cn/IDKJ-P/student/resStudentAPI'

        r = self.session.post(postUrl, json=data, headers=self.head)
        try:
            if r.json()['resCode'] != '0':
                print('预约失败')
                print(r.text)
                return False
            else:
                print('预约成功')
                return True
        except Exception as e:
            print('返回了err网页')
            return False


def readConfig():
    with open('config.json', encoding='utf-8') as file:
        return json.load(file)


def main():
    url = "https://pass.hust.edu.cn/cas/login?service=http://m.hust.edu.cn/wechat/apps_center.jsp"
    config = readConfig()
    # config = os.environ
    outSchool = OutSchool(config['USER_ID'], config['PASSWORD'])
    for i in range(4):
        if outSchool.login(url):
            print('第', i + 1, '次尝试，登录成功')
            outSchool.dateOutSchool(config, outSchool.getProfile())
            break
    else:
        print("连续四次登录失败，需要手动在网页登录一下")


if __name__ == '__main__':
    main()
