# Handshake + Dane + Flux

Run full TLS connections without a CA! DNSSEC.

## Compatibility note

This has only been tested on macOS and Ubuntu. Should work on other platforms too. For Ubuntu, you will need to install a keychain backend - https://pypi.org/project/keyrings.cryptfile/ has been tested and working.

## Minimum requirements

* You must control a handshake tld. Eg https://www.namebase.io/
* Minimum one server with great uptime and static IP. Better to split the DNS / keeper though
* FluxApp running with FluxVault image in agent configuration
* A way of resolving handshake domains in your browser. A great app: https://github.com/imperviousinc/fingertip
* Python 3.11. The install process for this on Windows, Ubuntu and Mac is pretty straightforward. See https://www.python.org/downloads/release/python-3112/ Just make sure you run the scripts after to update your path and restart your terminal. If this is an issue for you, as long as you have Docker installed, you can just run the `Keeper` as an image.

## Optional requirements

* More DNS Servers
* GeoIP backend for PDnS
* Split DNS server and Keeper (FluxVault image in keeper configuration)

## What it does

Current SSL/TLS technology requires that your local computer trust select remote parties to secure your connection, generally HTTPS. Handshake + DNS Based Authentication of Named Entities, which leverages DNSSEC for end to end security, allows a domain controller to create a DNS record with the hash of the certificate, which the user can hash against the webserver provided certificate which ensures authenticity. This means we don't need to trust any random intermediaries that our connection is secure. We know it is from start to finish. (Except the node owner of course)

## How it works

On your local computer or server you run the `Keeper`. This has all your private info, like nginx config, plugins, then connects to your FluxApps and PowerDNS server to maintain a current set of certificates, tlsa and a records. It connects every minute, for a health check and pulls the tlsa/a records if the node doesn't respond within 3 attempts. The DNS Records are set with a 5 minute TTL. It also installs, configures, and runs Nginx, which proxies the connection via the internal network to the http webserver.

### Step zero

TLDR; Just read / do this - https://blog.htools.work/posts/hns-pdns-nginx-part-1/ Set up the DNS server with DNSSEC, NS records and update the SOA to match something like `yourdomain. hostmaster.yourdomain. 30 10800 3600 604800 3600` It should only be the first part of the SOA your need to udpate.

### Step one

Point your handshake domain to your NameServers. This can take 6 hours or so to update due to zone updates.

### Step two

Generate an auth key with the `Keeper`. This stores the private key in your secure area, then gives you the address - this is passed into the FluxApp at runtime, this allows the FluxApp to validate via message signing that we are indeed who we say we are. This is far superior to any source address based validation. Run:

```
> fluxvault keeper keys create

Private key stored. Address to use on Agent: 1DE397KY38XWFGvZd64uyYJgWp94YRJDLe
```

```
> fluxvault keeper keys show-all

+------+------------------------------------+
|   id | address                            |
|------+------------------------------------|
|    5 | 1DE397KY38XWFGvZd64uyYJgWp94YRJDLe |
+------+------------------------------------+
```

### Step three

*In the near future, this will be a part of this application*

Spin up your FluxApp  - see the flux app `DaneNginx` for an example. The run command for the proxy should look like this `agent,--signed-vault-connections,--auth-id,<your address from step two>` It's just the agent running authentication - using a bitcoin address and message signing. There is also a webserver component, that just needs to be listening on 3000 for requests, you don't need to specify the port in the FluxApp config as we will proxy from the Agent.

### Step four

Install PowerDNS on your `Server` and configure it up. Locate the API key - we need this so can keeper can run it, for the Agent. Ubuntu 20.04 standard install works well. This server also needs docker on it to run the FluxAgent :wink: You can also run PowerDNS as a docker image, if you choose. Run the standard Flux agent `docker run --rm --name fluxagent_pdns --network=host -p 8888:8888 -it megachips/fluxvault:latest agent --signed-vault-connections --auth-id <your address from step 2> --disable-webserver`

Of note - our powerdns webserver is listening on localhost for API, for security reasons. In order to be able to access 127.0.0.1 from the docker image, we use `network=host` this is why we disable the agent webserver running on 2080. (We don't need it for this example)

### Step five

Configure up the `Keeper` All you need to do here is copy the user_config_example.yaml to user_config.yaml and put in your settings. See the main entrypoint `example_keeper.py`, this is the file we will run. When the `Keeper` first connects, it loads in the configured plugins, which upgrades the capability of the Agent for specific tasks. Here we are using a PDNS plugin for the Nameserver, and an nginx plugin for the Webproxy. You also need to add your PowerDNS API key, this is in the `/etc/powerdns/pdns.conf` file under the directive `api-key` on your powerdns server.

### Step six

make sure you're running python 3.11 and you have run `python3 -m pip install fluxvault jinja2`

Run the `Keeper` with the following: `python example_keeper.py`

At this point, depending if your app has been fully deployed, the `Keeper` should now poll the Flux network for your App's ip addresses and connect and configure the `Agents`. This will install certificates on the web proxies, generate a tlsa record based off this certificate, install and start nginx.

Query your dns server, the results should look something like this

yes, name as TLD wasn't my smartest move

```
> dig @116.251.187.92 _33443._tcp.davidwhite TLSA +dnssec

; <<>> DiG 9.10.6 <<>> @116.251.187.92 _33443._tcp.davidwhite TLSA +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14718
;; flags: qr aa rd; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;_33443._tcp.davidwhite.		IN	TLSA

;; ANSWER SECTION:
_33443._tcp.davidwhite.	300	IN	TLSA	3 1 1 DF161746CF5AE19C1EA075F1EB7DF7492097C70EDD844F7FD32EDFAE 7EC78DDA
_33443._tcp.davidwhite.	300	IN	TLSA	3 1 1 3AC6683BDD47AEF0A11A00E505C3523498FEF5A39B91A69BA19EA07B D13B5A1F
_33443._tcp.davidwhite.	300	IN	TLSA	3 1 1 7FAB9BE7B3623CCF278A3780C15DCBCE6FC9CFB6820A41DFDABFF125 5C49B221
_33443._tcp.davidwhite.	300	IN	TLSA	3 1 1 8E820B150DD35D12ED42AA66ECF403340F692CE583F481529FE3D925 6A4095DE
_33443._tcp.davidwhite.	300	IN	RRSIG	TLSA 13 3 300 20230406000000 20230316000000 63822 davidwhite. rpIQx3dEny4ElMwB8kGp+O0Ibbr9P9fefb5a5fZQsIu2GxLpxLgJL8Rj BINGeeQmylYp7c7J0Ngc2rVfqMIpeg==

;; Query time: 39 msec
;; SERVER: 116.251.187.92#53(116.251.187.92)
;; WHEN: Sun Mar 26 15:47:21 NZDT 2023
;; MSG SIZE  rcvd: 345
```