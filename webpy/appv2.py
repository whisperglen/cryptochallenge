import web
import hashlib
import hmac
from time import sleep
from time import perf_counter_ns

key = "yellow submarine"

urls = (
    #'/(.*)', 'hello'
    '/test(.*)', 'hello'
)
app = web.application(urls, globals())

class hello:
    def GET(self, name):
        user_data = web.input()
        if 'file' not in user_data: return web.webapi.BadRequest()
        if 'signature' not in user_data: return web.webapi.BadRequest()
        hmacobj = hmac.new(key.encode("UTF-8"), user_data['file'].encode("ascii"), hashlib.sha1);
        sigbytes = bytearray.fromhex(user_data['signature'])
        #print(user_data['signature'], end =" ")
        start = perf_counter_ns()
        count = 0
        for db,sb in zip(hmacobj.digest(), sigbytes) :
          #print(hex(db)+ " " + hex(sb))
          if db != sb:
            break
          sleep(0.005)
          count += 1
        end = perf_counter_ns()
        #print((end-start)/1000000)
        if(hmacobj.digest_size == count):
          return web.webapi.OK()
        else:
          return web.InternalError("NOK") #"<h1>" + str(count) + "</h1>"#
        #hsign = "hmacsha1:  " + hmacobj.hexdigest()
        #text1 = "file: " + user_data['file']
        #text2 = "signature: " + user_data['signature']
        text3 = "match: " + ("true" if(hmacobj.digest_size == count) else "false")
        #print(text1, text2)
        rettext = "<h1>"
        #rettext += "<br/>" + text1;
        #rettext += "<br/>" + text2;
        #rettext += "<br/>" + hsign;
        rettext += "<br/>" + text3;
        rettext += "</h1>";
        return rettext

if __name__ == "__main__":
    #app.run()
    web.httpserver.runsimple(app.wsgifunc(), ("127.0.0.1", 8080))