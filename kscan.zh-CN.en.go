package main

import (
	"kscan/app"
	"kscan/lib/color"
	"kscan/lib/fofa"
	"kscan/lib/gonmap"
	"kscan/lib/httpfinger"
	"kscan/lib/slog"
	"kscan/lib/spy"
	"kscan/lib/touch"
	"kscan/run"
	"os"
	"runtime"
	"time"
)
//logo information
const logo = `
 _   __
|#| /#/ Lightweight Asset Mapping Tool by: kv2	
|#|/#/  _____   _____ *  _     _   _
|#.#/  /Edge/  /Forum|  /#\   |#\ |#|
|##|   |#|__   |#|     /###\  |##\|#|
|#.#\  \#####\ |#|    /#/_\#\ |#.#.#|
|#|\#\ /\___|#||#|___/#/###\#\|#|\##|
|#| \#\\#####/ \####/#/v1.67\#|#| \#|

`

//help information
const help = `
optional arguments:
	-h , --help 	show this help message and exit
	-f , --fofa 	Get the detection object from fofa, you need to configure the environment variables in advance: FOFA_EMAIL, FOFA_TOKEN
	-t , --target 	Specify the detection target:
					IP address: 114.114.114.114
					IP address segment: 114.114.114.114/24, subnet mask less than 12 is not recommended
					IP address range: 114.114.114.114-115.115.115.115
					URL address: https://www.baidu.com
					File address: file:/tmp/target.txt
	--spy 			network segment detection mode, in this mode, the internal network segment reachable by the host will be automatically detected. The acceptable parameters are:
					(empty), 192, 10, 172, all, specified IP address (the IP address segment B will be detected as a surviving gateway)
	--check 		Fingerprinting the target address, only port detection will not be performed
	--scan 			will perform port scanning and fingerprinting on the target objects provided by --fofa and --spy
	--touch 		Get the return package of the specified port, you can use this parameter to get the return package and improve the fingerprint library, the format is: IP:PORT
	-p , --port 	scan the specified port, the default will scan TOP400, support: 80, 8080, 8088-8090
	-o , --output 	save scan results to file
	-oJ 			save the scan results to a file in json format
	-Pn 			After using this parameter, intelligent survivability detection will not be performed. Now intelligent survivability detection is enabled by default to improve efficiency.
	-Cn 			With this parameter, the console output will not be colored.
	--top 			Scan the filtered common ports TopX, up to 1000, the default is TOP400
	--proxy 		set proxy (socks5|socks4|https|http)://IP:Port
	--threads 		thread parameter, the default thread is 100, the maximum value is 2048
	--path 			specifies the directory to request access, only a single directory is supported
	--host 			specifies the header Host value for all requests
	--timeout 		set timeout
	--encoding  	Set the terminal output encoding, which can be specified as: gb2312, utf-8
	--hydra 		automatic blasting support protocol: ssh, rdp, ftp, smb, mysql, mssql, oracle, postgresql, mongodb, redis, all are enabled by default
hydra options:
	--hydra-user 	custom hydra blasting username: username or user1,user2 or file:username.txt
	--hydra-pass 	Custom hydra blasting password: password or pass1,pass2 or file:password.txt
					If there is a comma in the password, use \, to escape, other symbols do not need to be escaped
	--hydra-update  Customize the user name and password mode. If this parameter is carried, it is a new mode, and the user name and password will be added to the default dictionary. Otherwise the default dictionary will be replaced.
	--hydra-mod 	specifies the automatic brute force cracking module: rdp or rdp, ssh, smb
fofa options:
	--fofa-syntax 		will get fofa search syntax description
	--fofa-size 		will set the number of entries returned by fofa, the default is 100
	--fofa-fix-keyword  Modifies the keyword, and the {} in this parameter will eventually be replaced with the value of the -f parameter
`

const usage = "usage: kscan [-h,--help,--fofa-syntax] (-t,--target,-f,--fofa,--touch) [--spy] [-p,- -port|--top] [-o,--output] [-oJ] [--proxy] [--threads] [--path] [--host] [--timeout] [-Pn] [- Cn] [--check] [--encoding] [--hydra] [hydra options] [fofa options]\n\n"

const syntax = `title="beijing" 			searches for "Beijing" from the title -
header="elastic" 							searches for "elastic" from http headers -
body="Cyberspace Mapping" 					Search "Cyberspace Mapping" from the html body -
domain="qq.com" 							Search for websites with qq.com in the root domain name. -
icp="Jing ICP Certificate No. 030173" 		Find the website with the record number of "Jing ICP Certificate No. 030173" Search for website type assets
js_name="js/jquery.js" 						Find assets that contain js/jquery.js Search site type assets
js_md5="82ac3f14327a8b7ba49baa208d4eaa15" 	to find assets whose js source code matches -
icon_hash="-247388890" 						Search for assets that use this icon. For FOFA Premium members only
host=".gov.cn" 								Search ".gov.cn" from the url, use host as the name
port="6379" 								to find assets corresponding to port "6379" -
ip="1.1.1.1" 								Search for websites containing "1.1.1.1" from ip and use ip as the name
ip="220.181.111.1/24" 						Query the assets of network segment C whose IP is "220.181.111.1" -
status_code="402" 							Query server for assets with status "402" -
protocol="quic" 							Query the quic protocol asset to search for the specified protocol type (valid when port scanning is enabled)
country="CN" 								searches for assets in the specified country (code). -
region="Xinjiang" 							searches for assets in the specified administrative region. -
city="Changsha" 							searches for assets in the specified city. -
cert="baidu" 								searches for assets with baidu in the certificate. -
cert.subject="Oracle" 						searches for a certificate holder that is an Oracle property -
cert.issuer="DigiCert" 						searches for assets whose certificate issuer is DigiCert Inc -
cert.is_valid=true 							Verify that the certificate is valid only for FOFA premium members
type=service 								Search all protocol assets Search all protocol assets
os="centos" 								searches for CentOS assets. -
server=="Microsoft-IIS" 					searches for IIS 10 servers. -
app="Oracle" 								searches for Microsoft-Exchange devices -
after="2017" && before="2017-10-01" 		time range segment search -
asn="19551" 								Searches for assets with the specified asn. -
org="Amazon.com, Inc." 						Searches the property of the specified org (organization). -
base_protocol="udp" 						searches for assets with the specified udp protocol. -
is_fraud=falsenew 							Exclude phishing/fraud data -
is_honeypot=false 							Exclude honeypot data only for FOFA premium members
is_ipv6=true 								Search ipv6 assets Search ipv6 assets, only accept true and false.
is_domain=true 								Search the assets of the domain name to search the assets of the domain name, only accept true and false.
port_size="6" 								Query the assets with the number of open ports equal to "6" only for FOFA members
port_size_gt="6" 							Query assets with open ports greater than "6" only for FOFA members
port_size_lt="12" 							Query assets whose open port number is less than "12" is only available to FOFA members
ip_ports="80,161" 							Search for IPs that open ports 80 and 161 at the same time Search for IP assets that open ports 80 and 161 at the same time (asset data in ip units)
ip_country="CN" 							searches for ip assets in China. Search for IP assets in China
ip_region="Zhejiang" 						searches for ip assets in the specified administrative region. claim assets in a designated borough
ip_city="Hangzhou" 							Search for ip assets in the specified city. Search for assets in a given city
ip_after="2021-03-18" 						Search ip assets after 2021-03-18. Search ip assets after 2021-03-18
ip_before="2019-09-09" 						Search for ip assets before 2019-09-09. Search ip assets before 2019-09-09
`

func main() {
	startTime := time.Now()

	//Environment initialization
	Init()

	//check upgrade status
	//app.CheckUpdate()
	if app.Setting.Spy != "None" {
	InitSpy()
	spy.Start()
	if spy.Scan {
	app.Setting.HostTarget = spy.Target
	}
	}
	//fofa module initialization
	if len(app.Setting.Fofa) > 0 {
	InitFofa()
	}
	//kscan module start
	if len(app.Setting.UrlTarget) > 0 || len(app.Setting.HostTarget) > 0 {
	//Scan module initialization
	InitKscan()
	// start scanning
	run.Start(app.Setting)
	}
	//touch module start
	if app.Setting.Touch != "None" {
		_ = gonmap.Init(9, app.Setting.Timeout)

		r := touch.Touch(app.Setting.Touch)
		slog.Info("Netloc：", app.Setting.Touch)
		slog.Info("Status：", r.Status)
		slog.Info("Length：", r.Length)
		slog.Info("Response：")
		slog.Data(r.Text)
	}
	//calculate the running time of the program
	elapsed := time.Since(startTime)
	slog.Infof("The total execution time of the program is: [%s]", elapsed.String())
	slog.Info("If you have any questions, please submit bugs to my Github[https://github.com/lcvvvv/kscan/]")
}

func Init() {
	app.Args.SetLogo(logo)
	app.Args.SetUsage(usage)
	app.Args.SetHelp(help)
	app.Args.SetSyntax(syntax)
	//parameter initialization
	app.Args.Parse()
	//log initialization
	slog.SetEncoding(app.Args.Encoding)
	slog.SetPrintDebug(app.Args.Debug)
	//color package initialization
	app.Setting.CloseColor = color.Init(app.Args.CloseColor)
	// Initialize the configuration file
	app.ConfigInit()
	slog.Info("The current environment is: ", runtime.GOOS, ", the output encoding is: ", app.Setting.Encoding)
	if runtime.GOOS == "windows" && app.Setting.CloseColor == true {
		slog.Info("In Windows system, the color display is not enabled by default, you can enable it by adding an environment variable: KSCAN_COLOR=TRUE")
	}
}

func InitKscan() {
	//slog.Warning("Start reading scan object...")
	slog.Infof("Successfully read URL addresses: [%d]", len(app.Setting.UrlTarget))
	if app.Setting.Check == false {
		slog.Infof("Successfully read host addresses: [%d], ports to be detected: [%d]", len(app.Setting.HostTarget), len(app.Setting.HostTarget)*len(app. Setting.Port))
	}
	//Initialize HTTP fingerprint library
	r := httpfinger.Init()
	slog.Infof("Successfully loaded favicon fingerprints: [%d], keyword fingerprints: [%d]", r["FaviconHash"], r["KeywordFinger"])
	//gonmap probe/fingerprint library initialization
	r = gonmap.Init(9, app.Setting.Timeout)
	slog.Infof("Successfully loaded NMAP probes: [%d], fingerprints [%d]", r["PROBE"], r["MATCH"])
	//Gonmap application layer fingerprint identification initialization
	gonmap.InitAppBannerDiscernConfig(app.Setting.Host, app.Setting.Path, app.Setting.Proxy, app.Setting.Timeout)
}

func InitFofa() {
	email := os.Getenv("FOFA_EMAIL")
	key := os.Getenv("FOFA_KEY")
	if email == "" || key == "" {
		slog.Warning("Please configure environment variables before using -f/-fofa parameter: FOFA_EMAIL, FOFA_KEY")
		slog.Error("If you want to import port scan tasks from a file, use -t file:/path/to/file")
	}
	f := fofa.New(email, key)
	f.LoadArgs()
	f.SearchAll()
	if app.Setting.Check == false && app.Setting.Scan == false {
		slog.Warning("You can use the --check parameter to perform liveness and fingerprint detection on the fofa scan results, and you can use the --scan parameter to perform port scans on the fofa scan results")
	}
	if app.Setting.Check == true {
		slog.Warning("The check parameter is enabled, and now the fofa scan result will be subjected to liveness and fingerprint detection")
		f.Check()
	}
	if app.Setting.Scan == true {
		slog.Warning("The scan parameter is enabled, now port scan and fingerprint detection will be performed on the fofa scan result")
		f.Scan()
	}
}

func InitSpy() {
	spy.Keyword = app.Setting.Spy
	spy.Scan = app.Setting.Scan
}