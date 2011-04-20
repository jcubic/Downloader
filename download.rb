#!/usr/bin/ruby
#
# this script is for downloading files from File Hosting Sites
# Copyright (C) 2010 Jakub Jankiewicz (jcubic@onet.pl)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'net/http'
require 'net/https'
require 'uri'
require 'getoptlong'
require 'rexml/document'
require 'net/telnet'

class DownloadLimitException < Exception
end

class DownloadInProgress < Exception
end

class FileToBigException < Exception
end

class FileDeletedException < Exception
end

class LinkErrorException < Exception
end

class TransferLimitException < Exception
end

class ServerBusyException < Exception
end

class BadPasswordException < Exception
end

class NotConnectedException < Exception
end

ROUTER_LIVEBOX = 0
ROUTER_DLINK = 1

class Net::HTTP
  alias_method :old_initialize, :initialize
  def initialize(*args)
    old_initialize(*args)
    @ssl_context = OpenSSL::SSL::SSLContext.new
    @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
end


def title(string)
  return string.split(' ').map {|word| word.capitalize }.join(' ')
end

def host(url)
  url =~ /http:\/\/([^\/]*)\//
  return $1
end

def file(name)
  File.open(name) {|file|
    return file.read()
  }
end

def trail_slash(url)
  if url =~ /http:\/\/[^\/]*$/
    url += '/'
  end
  return url
end

class GetOpt
  def initialize(*options)
    opts = GetoptLong.new(*options)
    @opts = {}
    opts.each{|opt,arg|
      @opts[opt] = arg
    }
  end
  def [](key)
    return @opts[key]
  end
end

def response(url, cookies=nil, referer=nil)
  if url =~ /(\?.*)/
    query = $1
  end
  url = URI.parse(trail_slash(url))
  http = Net::HTTP.new(url.host)
  if !http
    raise NotConnectedException
  end
  headers = {}
  if cookies
    headers['Cookie'] = cookies
  end
  if referer
    headers['Referer'] = referer
  end
  begin
    if query
      path = url.path + query
    else
      path = url.path
    end
    res = http.get(path, headers)
  rescue NoMethodError
    #puts "fail: #{url}"
    raise NotConnectedException
  end
  return res
end

def head(url)
  if url =~ /(\?.*)/
    query = $1
  end
  url = URI.parse(trail_slash(url))
  http = Net::HTTP.new(url.host)
  return http.request_head(url.path + query)
end
  
def post(url, data)
  url = URI.parse(trail_slash(url))
  res = Net::HTTP.post_form(url, data)
  if !res
    raise NotConnectedException
  end
  return res.body
end

def wait_indicator(time)
  while time >= 0
    system('tput sc; echo -n " Wait ' + time.to_s + ' seconds  "; tput rc') 
    sleep(1)
    time -= 1
  end
  puts "done               "
end

def livebox_send(data, host, passwd)
  url = URI.parse("http://#{host}/SubmitInternetService")
  req = Net::HTTP::Post.new(url.path)
  req.basic_auth('admin', passwd)
  req.set_form_data(data)
  res = Net::HTTP.new(url.host, url.port).start {|http|
    http.request(req)
  }
  if res.code == 401
    raise BadPasswordException.new("bad password")
  else
    return res.body
  end
end



def livebox_connect(host, passwd)
  data = {'ACTION_CONNECT' => 'Po&#322;&#261;cz'}
  livebox_send(data, host, passwd)
end

def livebox_disconnect(host, passwd)
  data = {'ACTION_DISCONNECT'=> 'Roz&#322;&#261;cz'}
  livebox_send(data, host, passwd)
end

def dlink_reconnect(host, passwd)
  server = Net::Telnet::new('Host'=>host,
                            'Port'=> 23,
                            'Timeout'=>25,
                            'Prompt'=> />/)
  server.waitfor(/ogin:/)
  server.print("admin\n")
  server.waitfor(/ssword:/)
  server.print("#{passwd}\n")
  server.cmd("adsl connection --down")
  server.cmd("adsl connection --up")
  server.cmd("logout")
end


def wget(url, limit=false, filename=nil, referer=nil, cookies=nil, try=nil)
  agent = '"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.2.12) Gecko/20101027 Ubuntu/10.10 (maverick) Firefox/3.6.12 GTB7.1"'
  params = "-c -U #{agent} --keep-session-cookies --content-disposition" 
  if limit
    params += " --limit-rate=#{limit}" 
  end
  if filename
    params += " -O \"#{filename}\""
  end
  if cookies
    params += " --load-cookies=\"#{cookies}\""
  end
  if referer
    params += " --referer=\"#{referer}\""
  end
  if try
    params += " -t #{try}"
  end
  params += " -v"
  `wget #{params} "#{url}"`
end

def curl(url, limit=nil, filename=nil, referer=nil, cookies=nil)
  agent = '"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.2.12) Gecko/20101027 Ubuntu/10.10 (maverick) Firefox/3.6.12 GTB7.1"'
  params = "-A #{agent} -L --progress-bar" 
  if limit
    params += " --limit-rate #{limit}" 
  end
  if filename
    params += " -o \"#{filename}\""
  end
  if cookies
    params += " -b \"#{cookies}\""
  end
  if referer
    params += " -e \"#{referer}\""
  end
  #debug " -D -I -N" # no buffer debug only head
  `curl #{params} #{url}`
end


def four_shared(url, limit=false)
  res = response(url)
  referer = url
  if res.body =~ /a href="([^"]*)" class="dbtn"/
    page = response($1, res.response['set-cookie'], url).body
    cookies_filename = 'download_4shared_cookies.txt'
    File.open(cookies_filename, 'w') {|file|
      file.puts res.response['set-cookie']
    }
    if page =~ /<a href='([^']*)'>(Download file now|Pobierz plik teraz)<\/a>/
      url = $1
      page =~ /<b class="blue xlargen">([^<]*)</
      filename = $1
      page =~ /var c[= ]+([0-9]*);/
	  time = $1.to_i+1
      if RUBY_PLATFORM =~ /(:?mswin|mingw)/i
        puts "Wait #{time} seconds."
      else
        #use nice wait indicator on unix (require tput)
        wait_indicator(time)
      end
      
      curl(url, limit, filename, referer, res.response['set-cookie'])
    end
  end
end

def rapidshare(url, limit=false, router=nil)
  #download files using rapidshare api
  if not url =~ /files\/([^\/]*)\/(.*)/
    raise LinkErrorException
  end
  fileid = $1
  filename = $2
  host = "api.rapidshare.com"
  apiurl = '/cgi-bin/rsapi.cgi?sub=download'
  #use it for premium users
  #url += "&login=#{login}&password=#{passwd}"
  apiurl += "&fileid=#{fileid}&filename=#{filename}"
  http = Net::HTTP.new(host, 443)
  http.use_ssl = true
  res = http.get(apiurl).body
  #res = response(res['location']).body
  if res =~ /File deleted/
    raise FileDeletedException
  end
  if res =~ /You are already downloading/
    raise DownloadInProgress
  end
  if res =~ /All free download slots are full/
    raise ServerBusyException
  end
  if res =~ /You need RapidPro to download more files/
    raise DownloadInProgress
  end
  if res =~ /Please stop flooding our download/ and router
    raise DownloadLimitException
  end
  if res =~ /You need to wait ([0-9]*) seconds/
    time = $1.to_i
    if router
      raise DownloadLimitException
    else
      if RUBY_PLATFORM =~ /(:?mswin|mingw)/i
        puts "Wait #{time} seconds."
      else
        wait_indicator(time)
      end
      rapidshare(url, limit, router)
    end
  elsif res =~ /ERROR: /
    raise LinkErrorException
  elsif res =~ /DL:([^,]*),([^,]*),([^,]*)/
    host = $1
    dlauth = $2
    time = $3.to_i
    if RUBY_PLATFORM =~ /(:?mswin|mingw)/i
      puts "Wait #{time} seconds."
    else
      wait_indicator(time)
    end
    url = "http://#{host}/cgi-bin/rsapi.cgi?sub=download&"
    url += "dlauth=#{dlauth}&fileid=#{fileid}&filename=#{filename}"
    #head(url).response.each {|k,v| puts "#{k}: #{v}"}
    wget(url, limit, filename, nil, nil, 3)
  end
end

def przeklej_login_cookies(user, passwd)
  url = URI.parse('http://www.przeklej.pl/loguj')
  data = {
    'login[login]'=> user,
    'login[pass]' => passwd}
  res = Net::HTTP.post_form(url, data)
  return res.response['set-cookie']
end

def fix_filename(filename)
  filename = filename.gsub(/ +/, ' ')
  filename = filename.gsub(' .', '.')
  filename = title(filename)
  return filename
end

def przeklej(url, limit=false, user=nil, passwd=nil)
  referer = url
  if user and passwd
    cookies = przeklej_login_cookies(user, passwd)
    cookies_filename = 'download_przeklej_cookies.txt'
    File.open(cookies_filename, 'w') {|file|
      file.puts cookies
    }
    page = response(url, cookies).body
  else
    cookies_filename = nil
    page = response(url).body
  end
  if page =~ /Plik zosta/
    raise FileDeletedException
  end
  #if not loged
  if not page =~ /Wyloguj/
    loged = false
    if page =~ /pny <strong>abonament<\/strong>/
      raise FileToBigException
    end
  else
    loged = true
  end
  if page =~ /<p class="download-popup-abonament-button-box">[^<]*<a href="([^"]*)">/
    uri = $1
  elsif page =~ /<a class="download" href="([^"]*)"/
    uri = $1
  end
  if page =~ /B..dny parametr w linku/
    url =~ /.*\/(.*)/
    raise LinkErrorException $1
  end
  if page =~ /title="Pobierz plik">([^<]*)<\/a>/
    filename = fix_filename($1)
    if loged
      #send request (simulate XHR)
      page =~ /var myhref = "([^"]*)"/
      check = response("http://www.przeklej.pl#{$1}#{(rand*1000).floor}", cookies, url).body
      if check =~ /"return_code":1/
        raise TransferLimitException
      end
      res = response("http://www.przeklej.pl#{uri}", cookies, url).response
      if not res['Location'] =~ /http:\/\//
        url = "http://www.przeklej.pl#{res['Location']}"
      else
        url = res['Location']
      end
        wget(url, limit, filename, referer)
    else
      wget("http://www.przeklej.pl#{uri}", limit, filename, referer)
    end
  end
end

def wrzuta(url, limit=false)
  page = response(url).body
  #default values taken from decompiled swf music player
  if page =~ /'key' : '([^']*)',/
    key = $1
  else
    key = '4KWNcfGaCak'
  end
  if page =~ /'login' : '([^']*)',/
    login = $1
  else
    login = 'lifthrasil'
  end
  if page =~ /'host' : '([^']*)',/
    host = $1
  else
    host = 'labs.wrzuta.pl'
  end
  if page =~ /'site' : '([^']*)',/
    site = $1
  else
    site = 'wrzuta.pl'
  end
  if page =~ /'lang' : '([^']*)',/
    lang = $1
  else
    lang = 'pl'
  end
  if key and login and host and site and lang
    if lang == 'pl'
      _local2 = 'plik'
    else 
      _local2 = 'file'
    end
    rnd = (rand*1000000).floor
    url = "http://#{login}.#{host}/xml/#{_local2}/#{key}/sa/#{site}/#{rnd}"
    
    xml = REXML::Document.new(response(url).body).root
    url = xml.elements['//file/storeIds/fileId'][0]
    filename = xml.elements['//name'][0]
    wget(url, limit, filename)
  end
end

def download(url, limit, user=nil, passwd=nil, router=nil, router_passwd=nil)
  begin
    url = url.strip
    case host(url)
    when /.*\.wrzuta.pl/
      wrzuta(url, limit)
    when 'www.4shared.com'
      four_shared(url, limit)
    when /rapidshare.*/
      begin
        rapidshare(url, limit, router)
      rescue DownloadLimitException
        if router
          puts "Limit reached, change IP."
          #double check
          begin
            if router == ROUTER_DLINK
              dlink_reconnect('192.168.1.1', router_passwd)
              puts "wait 5 second to reconect the router"
              sleep(5)
            elsif router == ROUTER_LIVEBOX
              livebox_disconnect('192.168.1.1', router_passwd)
              livebox_connect('192.168.1.1', router_passwd)
            end
            rapidshare(url, limit, router)
          rescue DownloadLimitException
            download(url, limit, nil, nil, router, router_passwd)
          rescue BadPasswordException
            puts "Bad password"
          rescue ServerBusyException
            puts "Server is Buisy"
          rescue LinkErrorException
            puts "Link Error (#{url})"
          rescue FileDeletedException
            url =~ /.*\/(.*)/
            puts "File '#{$1}' was removed"
          end
        else
          puts "Limit Reached"
        end
      rescue LinkErrorException
        puts "Link Error (#{url})"
      rescue FileDeletedException
        url =~ /.*\/(.*)/
        puts "File '#{$1}' was removed"
      rescue ServerBusyException
        puts "Server is Buisy"
      rescue DownloadInProgress
        puts "You are already downloading"
      end
    when /(www\.)?przeklej\.pl/
      begin
        przeklej(url, limit)
      rescue FileToBigException
        if user and passwd
          begin
            przeklej(url, limit, user, passwd)
          rescue TransferLimitException
            puts "You can't download that file (buy more transfer)"
          end
        else
          puts "File too big for download (try to login)"
        end
      rescue FileDeletedException
        url =~ /.*\/(.*)/
        puts "File '#{$1}' Deleted"
      rescue LinkErrorException
        url =~ /.*\/(.*)/
        puts "Link Error (#{$1})"
      end
    else
      puts "unknown host \"#{host(url)}\" - skip"
    end
  rescue SocketError => e
    puts "'#{e.message}' probibly your internet connection is down"
    exit(1)
  end
end

def usage()
  puts "usage:"
  puts "download.rb [-u | --user <user>] [-p | --passwd <password>]"
  puts "            [-r | --limit-rate <limit>] [--help]"
  puts "            [-l | --livebox-passwd <password>]"
  puts "            (-f | --file <filename>) | <url>"
  puts "\n-u --user <user>      - user for przeklej.pl"
  puts "-p --passwd <password>  - passowrd for przeklej.pl"
  puts "-r --limit-rate <rate>  - slow down file transfer" 
  puts "-s --router-passwd      - password if you using router with ADSL"
  puts "                          for automatic reconect when download from"
  puts "                          rapidshare"
  puts "-d --router <name>        router livebox or dlink"
  puts "-f --file [filename]    - file with urls to download"
end

begin 
  opts = GetOpt.new(["--file", "-f", GetoptLong::REQUIRED_ARGUMENT],
                    ["--limit-rate", "-r", GetoptLong::REQUIRED_ARGUMENT],
                    ["--user", "-u", GetoptLong::REQUIRED_ARGUMENT],
                    ["--passwd", "-p", GetoptLong::REQUIRED_ARGUMENT],
                    ["--help", "-h", GetoptLong::NO_ARGUMENT],
                    ["--router-passwd", "-s", GetoptLong::REQUIRED_ARGUMENT],
                    ["--router", "-d", GetoptLong::REQUIRED_ARGUMENT])
rescue GetoptLong::InvalidOption
  usage
  exit(1)
end

if opts['--help']
  usage
  exit(0)
end

filename = opts['--file']
limit = opts['--limit-rate']
#user and password for 'przeklej.pl' only
user = opts['--user']
passwd = opts['--passwd']
router_passwd = opts['--router-passwd']

if opts['--router']
  case opts['--router'].downcase
  when 'livebox'
    router = ROUTER_LIVEBOX
  when 'dlink'
    router = ROUTER_DLINK
  else
    router = nil
  end
else
  router = nil
end

if filename
  begin
    File.open(filename) {|file|
      file.each{|url|
        #skip blank lines, comments and invalid urls
        if not url =~ /^ *$/ and not url =~ /^ *#.*$/ and url =~ /^http:\/\//
          begin
            puts "download: #{url}"
            download(url, limit, user, passwd, router, router_passwd)
          rescue Timeout::Error, Errno::ETIMEDOUT
            puts "timeout Error, try again"
            redo
          rescue NotConnectedException
            puts 'Not connected'
            break
          end
        end
      }
    }
  rescue Interrupt, Errno::EINTR
    #silent exit
    exit(1)
  
  end
else
  if ARGV.length == 0
    usage
  elsif not ARGV[0] =~ /^http:\/\//
    puts "Invalid url"
    usage
  else
    if passwd and user and host(ARGV[0]) != 'www.przeklej.pl'
      puts "[warring] password is used only in 'przeklej.pl' site - ignore"
    end
    begin
      download(ARGV[0], limit, user, passwd, router, router_passwd)
    rescue NotConnectedException
      puts 'Not connected'
    end
  end
end
