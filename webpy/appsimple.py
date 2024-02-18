import web
import hashlib
import hmac
from time import sleep
from time import perf_counter_ns
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

key = "yellow submarine"

class MyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        parsed = urlparse(self.path)
        user_data = parse_qs(parsed.query)
        #print(user_data)
        if 'file' not in user_data: self.send_response(400); self.end_headers(); return
        if 'signature' not in user_data: self.send_response(400); self.end_headers(); return
        #print(user_data['file'][0], user_data['signature'][0])
        hmacobj = hmac.new(key.encode("UTF-8"), user_data['file'][0].encode("ascii"), hashlib.sha1);
        sigbytes = bytearray.fromhex(user_data['signature'][0])
        #print(user_data['signature'], end =" ")
        start = perf_counter_ns()
        count = 0
        for db,sb in zip(hmacobj.digest(), sigbytes) :
          #print(hex(db)+ " " + hex(sb))
          if db != sb:
            break
          sleep(0.001)
          count += 1
        end = perf_counter_ns()
        #print((end-start)/1000000)
        if(hmacobj.digest_size == count):
          self.send_response(200);
        else:
          self.send_response(500);
        self.send_header("Content-Length", "0")
        self.end_headers();
        return
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
    httpd = HTTPServer(('localhost', 8080), MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()