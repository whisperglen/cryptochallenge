import web
import hashlib
import hmac
from time import sleep

key = "yellow submarine"

urls = (
    #'/(.*)', 'hello'
    '/test(.*)', 'hello'
)
app = web.application(urls, globals())

class hello:
    def GET(self, name):
        user_data = web.input()
        if 'file' not in user_data: return "<h1>Nothing to see here</h1>"
        hmacobj = hmac.new(key.encode("UTF-8"), user_data['file'].encode("ascii"), hashlib.sha1);
        sigbytes = bytearray.fromhex(user_data['signature'])
        for db,sb in zip(hmacobj.digest(), sigbytes) :
          #print(str(db)+ " " + str(sb))
          if db != sb:
            break
          sleep(0.05)
        hsign = "hmacsha1:  " + hmacobj.hexdigest()
        text1 = "file: " + user_data['file']
        text2 = "signature: " + user_data['signature']
        text3 = "match: " + ("true" if(hmacobj.hexdigest() == user_data['signature']) else "false")
        #print(text1, text2)
        rettext = "<h1>"
        rettext += "<br/>" + text1;
        rettext += "<br/>" + text2;
        #rettext += "<br/>" + hsign;
        rettext += "<br/>" + text3;
        rettext += "</h1>";
        return rettext

if __name__ == "__main__":
    app.run()