#!/usr/bin/ruby
#
# this script is for downloading files from File Hosting Sites
# Copyright (C) 2010 Jakub Jankiewicz
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

require "net/http"
require "uri"
require "getoptlong"

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

def get(url, cookies=nil, referer=nil)
  url = URI.parse(trail_slash(url))
  http = Net::HTTP.new(url.host)
  headers = {}
  if cookies
    headers['Cookie'] = cookies
  end
  if referer
    headers['Referer'] = referer
  end
  res = http.get(url.path, headers)
  return res.body
end

def post(url, data)
  url = URI.parse(trail_slash(url))
  res = Net::HTTP.post_form(url, data)
  return res.body
end


def wait_indicator(time)
  while time >= 0
    system('tput sc; echo -n "Wait ' + time.to_s + ' seconds  "; tput rc') 
    sleep(1)
    time -= 1
  end
  puts "done              "
end

def livebox_send(data, host, passwd)
  url = URI.parse("http://#{host}/SubmitInternetService")
  req = Net::HTTP::Post.new(url.path)
  req.basic_auth('admin', passwd)
  req.set_form_data(data)
  res = Net::HTTP.new(url.host, url.port).start {|http|
    http.request(req)
  }
  return res.body
end

def connect(host, passwd)
  data = {'ACTION_CONNECT' => 'Po&#322;&#261;cz'}
  livebox_send(data, host, passwd)
end

def disconnect(host, passwd)
  data = {'ACTION_DISCONNECT'=> 'Roz&#322;&#261;cz'}
  livebox_send(data, host, passwd)
end

def wget(url, limit=false, filename=nil, referer=nil, cookies=nil)
  params = '-c -U Mozilla --keep-session-cookies' 
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
  `wget #{params} "#{url}"`
end

def four_shared(url, limit=false)
  page = get(url)
  if page =~ /a href="([^"]*)" class="dbtn" tabindex="1"><span><span><font>Pobierz teraz<\/font>/
    page = get($1, nil, url)
    if page =~ /<a href='([^']*)'>Download file now<\/a>/
      url = $1
      page =~ /<b class="blue xlargen">([^<]*)</
      filename = $1
      page =~ /var c=([0-9]*);/
      if RUBY_PLATFORM =~ /(:?mswin|mingw)/i
        puts "Wait #{$1} seconds."
      else
        #use nice wait indicator on unix (require tput)
        wait_indicator($1.to_i)
      end
      wget(url, limit, filename)
    end
  end
end

def rapidshare(url, limit=false)
  page = get(url)
  if page =~ /The file could not be found/
    raise LinkErrorException
  end
  if page =~ /the file has been removed from the server/
    raise FileDeletedExepction
  end
  if page =~ /<form id="[^"]*" action="([^"]*)"/
    page = post($1, {'dl.start'=> 'Free'})
    if page =~ /You have reached the download limit for free-users/
      raise DownloadLimitException
    end
    if page =~ /Your IP address .* is already downloading a file/
      raise DownloadInProgress
    end
    page =~ /<form name="[^"]*" action="([^"]*)"/
    url = $1
    page =~ /var c=([0-9]*);/
    time = $1.to_i
    if RUBY_PLATFORM =~ /(:?mswin|mingw)/i
      puts "Wait #{$1} seconds."
    else
      wait_indicator(time)
    end
    wget(url, limit)
  end
end

def response(url, cookies=nil, referer=nil)
  url = URI.parse(trail_slash(url))
  http = Net::HTTP.new(url.host)
  headers = {}
  if cookies
    headers['Cookie'] = cookies
  end
  if referer
    headers['Referer'] = referer
  end
  res = http.get(url.path, headers)
  return res.response
end

def przeklej_login_cookies(user, passwd)
  url = URI.parse('http://www.przeklej.pl/loguj')
  data = {
    'login[login]'=> user,
    'login[pass]' => passwd}
  res = Net::HTTP.post_form(url, data)
  return res.response['set-cookie']
end

def przeklej_logout()
  url = 'http://przeklej.pl/wyloguj'
  return get(url)
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
    page = get(url, cookies)
  else
    cookies_filename = nil
    page = get(url)
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
    raise LinkErrorException
  end
  if page =~ /title="Pobierz plik">([^<]*)<\/a>/
    filename = fix_filename($1)
    if loged
      #send request (simulate XHR)
      page =~ /var myhref = "([^"]*)"/
      check = get("http://www.przeklej.pl#{$1}#{(rand*1000).floor}", cookies, url)
      if check =~ /"return_code":1/
        raise TransferLimitException
      end
      res = response("http://www.przeklej.pl#{uri}", cookies, url)
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
  if user and passwd
    przeklej_logout
  end
end

def download(url, limit, user=nil, passwd=nil, livebox_passwd=nil)
  url = url.strip
  case host(url)
  when 'www.4shared.com'
    four_shared(url, limit)
  when 'rapidshare.com'
    begin
      rapidshare(url, limit)
    rescue DownloadLimitException
      if livebox_passwd
        puts "Limit reached, change IP."
        #double check
        begin
          disconnect('192.168.1.1', livebox_passwd)
          connect('192.168.1.1', livebox_passwd)
          rapidshare(url, limit)
        rescue DownloadLimitException
          download(url, limit)
        end
      else
        puts "Limit Reached"
      end
    rescue LinkErrorException
      puts "Link Error"
    rescue FileDeletedException
      puts "File was removed"
    end
  when 'www.przeklej.pl'
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
      puts "File Deleted"
    rescue LinkErrorException
      puts "Link Error"
    end
  else
    puts "unknown host \"#{host(url)}\" - skip"
  end
end

def usage()
  puts "usage:"
  puts "download.rb [-u | --user <user>] [-p | --passwd <password>]"
  puts "            [-r | --limit-rate <limit>] [--help]"
  puts "            [-l | --livebox-passwd <password>]"
  puts "            (-f | --file <filename) | <url>"
  puts "-u --user [user]        - user for przeklej.pl"
  puts "-p --passwd [password]  - passowrd for przeklej.pl"
  puts "-r --limit-rate [rate]  - slow down file transfer" 
  puts "-l --livebox-passwd     - password if you using Orange livebox"
  puts "                          for automatic reconect (change ADSL dynamic IP)"
  puts "\n-f --file [filename]    - file with urls to download"
end

begin 
  opts = GetOpt.new(
                    ["--file", "-f", GetoptLong::REQUIRED_ARGUMENT],
                    ["--limit-rate", "-r", GetoptLong::REQUIRED_ARGUMENT],
                    ["--user", "-u", GetoptLong::REQUIRED_ARGUMENT],
                    ["--passwd", "-p", GetoptLong::REQUIRED_ARGUMENT],
                    ["--help", "-h", GetoptLong::NO_ARGUMENT],
                    ["--livebox-passwd", "-l", GetoptLong::REQUIRED_ARGUMENT])
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
livebox_passwd = opts['--livebox-passwd']


if filename
  File.open(filename) {|file|
    file.each{|url|
      #skip blank lines, comments and invalid urls
      if not url =~ /^ *$/ and not url =~ /^ *#.*$/ and url =~ /^http:\/\//
        download(url, limit, user, passwd, livebox_passwd)
      end
    }
  }
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
    download(ARGV[0], limit, user, passwd, livebox_passwd)
  end
end
