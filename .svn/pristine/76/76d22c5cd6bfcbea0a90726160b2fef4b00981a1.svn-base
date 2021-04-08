#!/usr/bin/env python3

'''
Sample password reset process which is vulnerable to padding oracle attacks

Copyright (C) 2016-2017 Blindspot Security LLC
Author: Timothy D. Morgan

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License, version 3,
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import http.server
import tokenutils

listen_ip = '127.0.0.1'
listen_port = 8888


class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        
    def do_GET(s):
        if s.path.startswith('/generate-reset-token'):
            s.send_response(200)
            s.send_header("Content-Type", "text/html; charset=utf-8")
            s.end_headers()
            
            s.wfile.write(b"<html><head><title>Reset Your Password</title></head>")
            s.wfile.write(b"<body>")
            user = s.path.split('user=')[1]
            url = 'http://%s:%d/reset-password?token=%s' % (listen_ip,listen_port,tokenutils.generateResetToken(user))
            s.wfile.write(('<h4>If this were a real application, we would have emailed the user "%s" the following URL so they could reset their password:</h4>' % user).encode('utf-8'))
            s.wfile.write(('<code><a href="%s">%s</a></code>' % (url,url)).encode('utf-8'))
            s.wfile.write(b"</body></html>")

        elif s.path.startswith('/reset-password'):
            token = s.path.split('token=')[1]
            result,info = tokenutils.validateResetToken(token)
            if result:
                s.send_response(200)
                s.send_header("Content-type", "text/html; charset=utf-8")
                s.end_headers()
                
                s.wfile.write(b"<html><head><title>Reset Your Password</title></head>")
                s.wfile.write(("<body><p>Hello <b>%s</b>, you may now reset your password:</p>" % info['user']).encode('utf-8'))
                s.wfile.write(b"<p>New password: <input type='password' /></p>")
                s.wfile.write(b"<p>Verify password: <input type='password' /></p>")
                s.wfile.write(b"<p><input type='button' value='Save' /></p>")
                s.wfile.write(b"</body></html>")
            else:
                s.send_response(200)
                s.send_header("Content-type", "text/html; charset=utf-8")
                s.end_headers()

                s.wfile.write(b"<html><head><title>Reset Your Password</title></head>")
                s.wfile.write(b"<body><p>Oops! There was a problem with your reset token</p>")
                s.wfile.write(b"<p>ERROR: <b>%s</b></p>" % info.encode('utf-8'))
                s.wfile.write(("<p>Please <a href='http://%s:%d/generate-reset-token?user=bob'>return here</a> to try again.</p>" % (listen_ip,listen_port)).encode('utf-8'))
                s.wfile.write(b"</body></html>")

        else:
            s.send_response(404)
            s.send_header("Content-type", "text/html; charset=utf-8")
            s.end_headers()
            
            s.wfile.write(b"<html><head><title>Not Found</title></head>")
            s.wfile.write(b"<body><p>Greetings traveler.  We think you want to start at ")
            s.wfile.write(("<a href='http://%s:%d/generate-reset-token?user=bob'>this page</a>.</p>" % (listen_ip,listen_port)).encode('utf-8'))
            s.wfile.write(b"</body></html>")


if __name__ == '__main__':
    httpd = http.server.HTTPServer((listen_ip, listen_port), MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
