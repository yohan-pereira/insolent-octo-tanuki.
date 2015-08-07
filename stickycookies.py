#!/usr/bin/env python
"""
This example builds on mitmproxy's base proxying infrastructure to
implement functionality similar to the "sticky cookies" option.

Heads Up: In the majority of cases, you want to use inline scripts.
"""
import os
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
import pprint
import copy
import re
from datetime import datetime


def cookie_name(cookie):
    return cookie.split("=")[0].strip()

def browser_cookie_value(cookie):
    return "=".join(cookie.split("=")[1:])

def update_value(cookie, value):
    name = cookie_name(cookie)
    components = cookie.split(";")
    components[0] = str(name) + "=" + str(value) 
    return ";".join(components)

def is_expired(cookie):
    cookie_l = cookie.lower()
    if not ("expiry" in cookie_l or "max-age" in cookie_l):
        return False
    attrs = cookie_atrs_to_map(cookie)
    if "max-age" in attrs:
        max_age = int(attrs["max-age"].strip())
        return max_age < 0
    elif "expires" in attrs:
        expiry_date = datetime.strptime(attrs["expires"].strip(), "%a, %d-%b-%Y %H:%M:%S %Z")
        return expiry_date < datetime.now()
    else :
        return False

#converts a list of cookies to a map of the form cookie_name -> cookie_string
def mapify(cookies):
    cookie_names = map(lambda c: cookie_name(c).lower(), cookies) 
    return dict(zip(cookie_names, cookies))

#converts a cookie into a map, ignoring attributes without values
def cookie_atrs_to_map(cookie):
    return dict(map(lambda string: [cookie_name(string).lower(), browser_cookie_value(string)], filter(lambda string: "=" in string, cookie.split(";"))[1:]))

def update_server_cookies(cookies, server_cookies):
    cookies.update(mapify(server_cookies))
    for expired_cookie in map(cookie_name, filter(is_expired, server_cookies)):
        print ("deleting expired cookie", expired_cookie)
        del cookies[expired_cookie]
    
    

def update_cookie_values(cookies, browser_cookies):
    new_cookies = mapify(browser_cookies[0].split(";"))
    for cookie_name in new_cookies:
        if cookie_name in cookies:
            cookie = cookies[cookie_name]
            cookies[cookie_name] = update_value(cookie, browser_cookie_value(new_cookies[cookie_name]))
            print "updating cookie "+cookie_name+" with new value " + browser_cookie_value(new_cookies[cookie_name])
        #else :
        #    print "adding new cookie "+cookie_name+" with value " + new_cookies[cookie_name]
        #    cookies[cookie_name] = new_cookies[cookie_name]


#server cookie 'id=2277ccced40300e5||t=1438870334|et=730|cs=002213fd4857d20d2057a72731; expires=Sat, 05-Aug-2017 14:12:14 GMT; path=/; domain=.doubleclick.net'
#browser cookie 'io=Z8MPB7HqeHzyG7qvt2Q0; _ga=GA1.2.1678911751.1438930512'

class StickyMaster(controller.Master):
    def __init__(self, server):
        print "starting"
        controller.Master.__init__(self, server)
        self.stickyhosts = {}
        self.relay = {}
        self.pp = pprint.PrettyPrinter(indent=4)

    #def __init__(self):
    #    self.stickyhosts = {}

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.pp.pprint(self.stickyhosts)
            self.shutdown()

    def handle_request(self, flow):
        hid = (flow.request.host, flow.request.port)
        #if ("browserstack" not in flow.response.host):
        #    flow.reply()
        #    return
        print ("request ",flow.request.host, flow.request.port, flow.id )
        if flow.request.headers["cookie"] and hid in self.stickyhosts:
            #self.stickyhosts[hid] = mapify(flow.request.headers["cookie"])
            #self.stickyhosts[hid] = flow.request.headers["cookie"]
            #print ("not reseting browser cookies for ", flow.request.host, flow.request.headers["cookie"])
            update_cookie_values(self.stickyhosts[hid], flow.request.headers["cookie"])
        elif hid in self.stickyhosts:
            print ("forwarding cookies for ", flow.request.host, flow.request.port, self.stickyhosts[hid])
            #cookies = self.stickyhosts[hid]
            cookies = self.stickyhosts[hid].values()
            flow.request.headers["cookie"] = copy.copy(cookies)
            self.relay[flow.id] = cookies
        flow.reply()

    def handle_response(self, flow):
        hid = (flow.request.host, flow.request.port)
        #if ("browserstack" not in flow.request.host):
        #    flow.reply()
        #    return

        print("resopnse ",flow.request.host, flow.request.port, flow.id)
        last_cookies_sent = self.relay.pop(flow.id, None)
        if flow.response.headers["set-cookie"]:
            if not hid in self.stickyhosts:
                self.stickyhosts[hid] = {}
            update_server_cookies(self.stickyhosts[hid], flow.response.headers["set-cookie"])
            flow.response.headers["set-cookie"] = copy.copy(self.stickyhosts[hid].values())
            #self.stickyhosts[hid] = flow.response.headers["set-cookie"]
            print ("storing new cookies for ", flow.request.host, flow.request.port, self.stickyhosts[hid])
        elif last_cookies_sent:
            print ("returning old cookies for ", flow.request.host, flow.request.port, self.stickyhosts[hid])
            flow.response.headers["set-cookie"] = last_cookies_sent
            #self.stickyhosts.pop(hid, None)
        flow.reply()


config = proxy.ProxyConfig(port=9000)
server = ProxyServer(config)
m = StickyMaster(server)
m.run()

#m = StickyMaster()
#
#def responseheaders(context, flow):
#    m.handle_response(flow)
#
#def request(context, flow):
#    m.handle_request(flow)
#


