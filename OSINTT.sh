
echo "Some checks are running. Sit back this may take couple of minutes. Press Ctrl + C to skip update and upgrade"
echo "Remaining are important. Recommended not to skip."
echo ""
echo "[ * ] Auto update in progress........"
echo ""
sudo apt-get update 2>/dev/null
echo ""
echo "[ * ] Auto upgrade in progress........"
echo ""
sudo apt-get upgrade -y 2>/dev/null
echo ""
echo "[ * ] Auto installing xterm in progress........"
echo ""
sudo apt-get install xterm 2>/dev/null
echo ""
echo "[ * ] Auto installing go in progress........"
echo ""
sudo apt-get install go 2>/dev/null
echo ""
echo "[ * ] Auto installing python3 in progress........"
echo ""
sudo apt-get install python3 2>/dev/null
echo ""
echo "[ * ] Auto Installing python3 pip in progress........"
echo ""
sudo apt-get install python3-pip 2>/dev/null
echo ""
read -p "Is Google Chrome installed on your system (0/1) [ 0 = False, 1 = True ]:  " gc
if [ "$gc" -eq 0 ]
then
	wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb 2>/dev/null
	sudo apt install ./google-chrome-stable_current_amd64.deb 2>/dev/null
	echo ""
fi
starting () { #Starting of the script
echo ""
echo ""
figlet -f /home/phoenix/3d.flf O S I N T T #Printing my Name
echo ""
echo  "\t\t\t\t\033[5mBy Ayush Pritam Bagde\033[0m"
echo ""
echo "1.  Username"
echo "2.  Email Address"
echo "3.  Domain Name"
echo "4.  IP Address"
echo "5.  Images / Videos / Docs"
echo "6.  Social Networks"
echo "7.  Instant Messaging"
echo "8.  People Search Engines"
echo "9.  Dating"
echo "10. Telephone Numbers"
echo "11. Public Records"
echo "12. Business Records"
echo "13. Transportation"
echo "14. Geolocation Tools/Maps"
echo "15. Search Engines"
echo "16. Forums/Blogs/IRC"
echo "17. Archives"
echo "18. Language Translation"
echo "19. Metadata"
echo "20. Mobile Emulation"
echo "21. Terrorism"
echo "22. Dark Web"
echo "23. Digital Currency"
echo "24. Classifieds"
echo "25. Encoding/Decoding"
echo "26. Tools"
echo "27. Malicious File Analysis"
echo "28. Exploits and Advisories"
echo "29. Threat Intelligence"
echo "30. OpSec"
echo "31. Docuemntation"
echo "32. Training"
echo ""
read -p "Enter OSINT Terminal Number from (1-32): " choice
}


username () { 

if [ $choice -eq 1 ]
then
	echo "1. Username search Engines"
	echo "2. Specific Sites"
	read -p "Enter your option: " option
	if [ $option -eq 1 ]
	then
		echo "1. WhatsMyName"
		echo "2. Maigret (T)"
		echo "3. sherlock (T)"
		echo "4. knowEm"
		echo "5. NameCheckr"
		echo ""
		read -p "Enter your option: " username_SE
		if [ $username_SE -eq 1 ]
		then
			google-chrome https://whatsmyname.app/ 2>/dev/null
	elif [ $username_SE -eq 2 ]
		then
			if [ -d maigret ]
			then
			cd maigret	
			read -p "Enter username: " username
			sudo python3 maigret --ids --print-found --skip-errors $username
			else
			sudo git clone https://github.com/soxoj/maigret.git
			cd maigret
			sudo apt-get install python3-pip
			sudo pip3 install -r requirements.txt
			read -p "Enter username: " username
			sudo python3 maigret --ids --print-found --skip-errors $username
			echo "For advanced search use python3 maigret --help"
		fi
	elif [ $username_SE -eq 3 ]
		then
			
			if [ -d sherlock ]
			then
				read -p "Enter username: " username
				sudo python3 sherlock/sherlock/sherlock.py $username
			else
				sudo git clone https://github.com/sherlock-project/sherlock.git
				cd sherlock
				sudo python3 -m pip install -r requirements.txt
				read -p "Enter username: " username
				sudo python3 sherlock/sherlock/sherlock.py -v $username
				echo "For Advanced Search use python3 Sherlock --help"
			fi
	elif [ $username_SE -eq 4 ]
			then
				google-chrome https://knowem.com/ 2>/dev/null
	elif [ $username_SE -eq 5 ]
			then
				google-chrome https://www.namecheckr.com/ 2>/dev/null
			fi
elif [ $option -eq 2 ]
	then
		echo "1. Amazon Usernames (M)"
		echo "2. Tinder Usernames (M)"
		echo "3. Keybase"
		echo "4. MIT PGP Key Server"
		read -p "Enter your option: " Specific_sites
		if [ $Specific_sites -eq 1 ]
		then
			read -p "Enter your username: " username
			google-chrome site:amazon.com $username 2>/dev/null
		elif [ $Specific_sites -eq 2 ]
			then
				read -p "Enter username: " username
				google-chrome https://tinder.com/@$username 2>/dev/null
			elif [ $Specific_sites -eq 3 ]
				then
					google-chrome https://keybase.io/ 2>/dev/null
				elif [ $Specific_sites -eq 4 ]
					then
						google-chrome http://pgp.mit.edu/ 2>/dev/null
					fi
fi
fi
}

email_address () {

	echo "1. Email Search"
	echo "2. Common Email Formats"
	echo "3. Email Verification"
	echo "4. Breach Data"
	echo "5. Spam Reputation Lists"
	echo "6. Mail Blackists"
	echo ""
	read -p "Enter your option: " option

	if [ $option -eq 1 ]
	then
		echo "1. ThatsThem"
		echo "2. Hunter"
		echo "3. Email to Address (R) "
		echo "4. Pipl"
		echo "5. VoilaNorbert"
		echo "6. theHarvester (T)"
		echo "7. infoga (T)"
		echo "8. Skymen"
		echo ""
		read -p "Enter your option: " Email_Search
		if [ $Email_Search -eq 1 ]
		then
			google-chrome https://thatsthem.com/ 2>/dev/null
		elif [ $Email_Search -eq 2 ]
			then
				google-chrome https://hunter.io/ 2>/dev/null
			elif [ $Email_Search -eq 3 ]
				then
					google-chrome https://www.melissa.com/v2/lookups/emailcheck/email/ 2>/dev/null
				elif [ $Email_Search -eq 4 ]
					then
						google-chrome https://pipl.com/ 2>/dev/null
					elif [ $Email_Search -eq 5 ]
						then
							google-chrome https://www.voilanorbert.com/ 2>/dev/null
						elif [ $Email_Search -eq 6 ]
							then
									sudo apt-get update
									read -p "Enter Domain Name: " domain
									sudo theHarvester -d $domain -l 500 -b all
							elif [ $Email_Search -eq 7 ]
								then
									if [ -d Infoga ]
									then
									sudo apt-get update
									sudo python Infoga/setup.py install
									echo -p "Enter any domain: " $domain
									sudo python Infoga/infoga.py -d -v $domain
								else
									sudo git clone https://github.com/m4ll0k/Infoga.git
									sudo apt-get update
								fi

									elif [ $Email_Search -eq 8 ]
									then
										google-chrome http://www.skymem.info/ 2>/dev/null
									fi
	elif [ $option -eq 2 ]
	then
										echo ""
										echo "1. Email Format"
										echo "2. Toofr"
										echo "3. Email Permutator"
										echo "4. OneLook Reverse Dictionary and Thesaurus"
										read -p "Enter your option: " common_email_formats
										if [ $common_email_formats -eq 1 ]
										then
											google-chrome https://www.email-format.com/ 2>/dev/null
										elif [ $common_email_formats -eq 2 ]
											then
												google-chrome https://www.findemails.com/ 2>/dev/null
											elif [ $common_email_formats -eq 3 ]
												then
													google-chrome http://metricsparrow.com/toolkit/email-permutator/ 2>/dev/null
												elif [ $common_email_formats -eq 4 ]
													then
														google-chrome https://www.onelook.com/reverse-dictionary.shtml 2>/dev/null
													fi
	elif [ $option -eq 3 ]
	then
													echo "1. MailTester"
													echo "2. VerifyEmail"
													echo "3. Email Validator"
													echo "4. BytePlant Email Validator"
													echo "5. Read notify"
													echo "6. Email Reputation"
													echo "7. MailboxValidator"
													echo ""
													read -p "Enter your Option: " email_verification
													if [ $email_verification -eq 1 ]
													then
														google-chrome http://mailtester.com/testmail.php 2>/dev/null
												elif [ $email_verification -eq 2 ]
													then
													google-chrome https://verify-email.org/ 2>/dev/null
												elif [ $email_verification -eq 3 ]
													then
													google-chrome http://e-mailvalidator.com/index.php 2>/dev/null
												elif [ $email_verification -eq 4 ]
													then
													google-chrome https://www.email-validator.net/ 2>/dev/null
												elif [ $email_verification -eq 5 ]
													then
													google-chrome https://www.readnotify.com// 2>/dev/null
												elif [ $email_verification -eq 6 ]
													then
													google-chrome https://emailrep.io/ 2>/dev/null
												elif [ $email_verification -eq 7 ]
													then
													google-chrome https://www.mailboxvalidator.com/demo 2>/dev/null
												fi
	elif [ $option -eq 4 ]
	then
													echo "1. Have I been pwned?"
													echo "2. DeHashed"
													echo "3. Intelligence X"
													echo "4. Vigilante.pw"
													echo "5. Breach or clear"
													echo "6. Ashley Medison Emails"
													echo ""
													read -p "Enter your option: " breach_data
													if [ $breach_data -eq 1 ]
													then
														google-chrome https://haveibeenpwned.com/ 2>/dev/null
													elif [ $breach_data -eq 2 ]
														then
															google-chrome https://dehashed.com/ 2>/dev/null
														elif [ $breach_data -eq 3 ]
															then
																google-chrome https://intelx.io/ 2>/dev/null
															elif [ $breach_data -eq 4 ]
																then
																	google-chrome https://dehashed.com/2>/dev/null
																elif [ $breach_data -eq 5 ]
																	then
																		google-chrome http://breachorclear.jesterscourt.cc/ 2>/dev/null
																	elif [ $breach_data -eq 6 ]
																		then
																			google-chrome https://ashley.cynic.al/ 2>/dev/null
												fi
	elif [ $option -eq 5 ]
	then
													echo "1. Spam Reputation Lists"
													echo ""
													read -p "Enter your option: " spam_reputation_lists
													if [ $spam_reputation_lists -eq 1 ]
													then
														google-chrome http://www.tcpiputils.com/dns-blackhole-list 2>/dev/null
													fi
	elif [ $option -eq 6 ]
	then
													echo "1. Mail Blackists"
													echo ""
													read -p "Enter your option: " mail_blacklists
													if [ $mail_blacklists -eq 1 ]
													then
														google-chrome https://mxtoolbox.com/ 2>/dev/null
													fi
												fi
}

domain_name () {

	echo "1. Whois Records"
	echo "2. Subdomains"
	echo "3. Discovery"
	echo "4. Certificate Search"
	echo "5. PassiveDNS"
	echo "6. Reputation"
	echo "7. Typosquatting"
	echo "8. Analytics"
	echo "9. URL Expanders"
	echo "10. Change Detection"
	echo "11. Social Analysis"
	echo "12. DNSSEC"
	echo "13. Cloud Resources"
	echo "14. Vulnerabilities"
	echo "15. Tools"
	read -p "Enter your option: " Domain_name
	echo ""
	if [ $Domain_name -eq 1 ]
	then
		echo "1. DNStable"
		echo "2. Domain Dossier"
		echo "3. DomainIQ"
		echo "4. Domain Big Data"
		echo "5. Whoisology"
		echo "6. WHois ARIN"
		echo "7. DNSstuff"
		echo "8. Robtex (R)"
		echo "9. Domaincrawler.com"
		echo "10. MarkMonitor Whois Search"
		echo "11. easyWhois"
		echo "12. Website Informer"
		echo "13. Who.is"
		echo "14. Whois AMped"
		echo "15. ViewDNS.info"
		echo "16. Domainsdb.info"
		echo "17. IP2WHOIS"
		echo ""
		read -p "Enter your option: " whois_records
	if [ $whois_records -eq 17 ]
	then
		google-chrome https://www.ip2whois.com/ 2>/dev/null
	elif [ $whois_records -eq 16 ]
		then
			google-chrome https://domainsdb.info/ 2>/dev/null
		elif [ $whois_records -eq 15 ]
			then
				google-chrome https://viewdns.info/ 2>/dev/null
			elif [ $whois_records -eq 14 ]
				then
					google-chrome https://whoisamped.com/ 2>/dev/null
				elif [ $whois_records -eq 13 ]
					then
						google-chrome https://who.is/ 2>/dev/null
					elif [ $whois_records -eq 12 ]
						then
							google-chrome https://website.informer.com/ 2>/dev/null
						elif [ $whois_records -eq 11 ]
							then
								google-chrome https://domainhelp.com/ 2>/dev/null
							elif [ $whois_records -eq 10 ]
								then
									google-chrome https://whois-webform.markmonitor.com/whois/ 2>/dev/null
								elif [ $whois_records -eq 9 ]
									then
										google-chrome https://domaincrawler.com/ 2>/dev/null
									elif [ $whois_records -eq 8 ]
										then
											google-chrome https://www.robtex.com/ 2>/dev/null
										elif [ $whois_records -eq 7 ]
											then
												google-chrome https://www.dnsstuff.com/freetools 2>/dev/null
										elif [ $whois_records -eq 6 ]
											then
												google-chrome https://whois.arin.net/ui/advanced.jsp 2>/dev/null
											elif [ $whois_records -eq 5 ]
												then
													google-chrome https://whoisology.com/#advanced 2>/dev/null
												elif [ $whois_records -eq 4 ]
													then
														google-chrome https://domainbigdata.com/ 2>/dev/null
													elif [ $whois_records -eq 3 ]
														then
															google-chrome https://www.domainiq.com/ 2>/dev/null
														elif [ $whois_records -eq 2 ]
															then
																google-chrome https://centralops.net/co/DomainDossier.aspx 2>/dev/null
															elif [ $whois_records -eq 1 ]
																then
																	google-chrome https://spyse.com/tools/dns-lookup 2>/dev/null
																fi

		elif [ $Domain_name -eq 2 ]
		then
			echo "1. Aquatone (T)"
			echo "2. FindSubDomains"
			echo "3. Google Subdomains (D)"
			echo "4. Recon-ng (T)"
			echo "5. XRay"
			echo "6. DNS Recon (T)"
			echo "7. Gobuster"
			echo "8. Fierce Domain Scanner"
			echo "9. Bluto"
			echo "10. theHarvester"
			echo "11. Pentest-tools.com Subdomains"
			echo "12. SecLists DNS Subdomains"
			echo "13. Sublister3r"
			echo "14. AltDNS (T)"
			read -p "Enter your option: " Subdomains
			if [ $Subdomains -eq 1 ]
			then
				sudo git clone https://github.com/michenriksen/aquatone.git
				google-chrome https://github.com/michenriksen/aquatone 2>/dev/null
			elif [ $Subdomains -eq 2 ]
				then
					google-chrome https://spyse.com/tools/subdomain-finder 2>/dev/null
				elif [ $Subdomains -eq 3 ]
					then
						echo "https://www.google.com/?gws_rd=ssl#q=site:<domain.com>"
					elif [ $Subdomains -eq 4 ]
						then
							echo "To Start: sudo recon-ng"
							sudo recon-ng --help
						elif [ $Subdomains -eq 5 ]
							then
								if [ -d xray ]
								then
									sudo apt-get install golang
									export GOPATH=/root/go-workspace >> ~/.bashrc
									export GOROOT=/usr/local/go >> ~/.bashrc
									PATH=$PATH:$GOROOT/bin/:$GOPATH/bin >> ~/.bashrc
							echo "Usage: xray -shodan-key YOUR_SHODAN_API_KEY -domain TARGET_DOMAIN"
   							else
							sudo git clone https://github.com/evilsocket/xray
							cd xray
							sudo apt-get install golang
							export GOPATH=/root/go-workspace >> ~/.bashrc
							export GOROOT=/usr/local/go >> ~/.bashrc
							PATH=$PATH:$GOROOT/bin/:$GOPATH/bin >> ~/.bashrc
							cd xray && make
						fi
					elif [ $Subdomains -eq 6 ]
						then
							sudo dnsrecon -h
						elif [ $Subdomains -eq 7 ]
							then
								read -p "Enter the URL: " URL
								xterm -e gobuster dir -u $URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 2>/dev/null 
								xterm -e gobuster dns -u $URL -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt 2>/dev/null
								sudo gobuster -h
								echo ""
							elif [ $Subdomains -eq 8 ]
								then
									read -p "Enter Domain Name: " dns
									sudo fierce --dns $dns
								elif [ $Subdomains -eq 9 ]
									then
										sudo pip install bluto
										sudo bluto -h
										echo "For more information visit: https://github.com/darryllane/Bluto"
									elif [ $Subdomains -eq 10 ]
										then
											sudo apt-get update
											read -p "Enter Domain Name: " domain
											sudo theHarvester -d $domain -l 500 -b all
										elif [ $Subdomains -eq 11 ]
											then
												google-chrome https://pentest-tools.com/information-gathering/find-subdomains-of-domain
											elif [ $Subdomains -eq 12 ]
												then
													ls /usr/share/wordlists/seclists/Discovery/DNS/ 
													echo "You can use these wordlists for DNS bruteforcing"
												elif [ $Subdomains -eq 13 ]
													then
														sudo sublist3r -h
														read -p "Enter domain: " domain
														sudo sublist3r -d $domain
													elif [ $Subdomains -eq 14 ]
														then
															sudo pip3 install py-altdns==1.0.2
															sudo altdns -h

					elif [ $domain -eq 3 ]
						then
							echo "1. Shodan"
							echo "2. Kraken"
							echo "3. urlscan.io"
							echo "4. Daily DNS Changes"
							echo "5. SameID"
							echo "6. Redirect Detective"
							echo "7. Sitediff"
							echo "8. AnalyzeID"
							read -p "Enter your option: " Discovery
							if [ "$Discovery" -eq 1 ]
							then
								google-chrome https://www.shodan.io/ 2>/dev/null
							elif [ "$Discovery" -eq 2 ]
								then
									if [ -d Kraken ]
									then
										sudo ./Kraken/setup.sh
									else
										sudo git clone https://github.com/Sw4mpf0x/Kraken.git
										cd Kraken
										chmod 755 setup.sh
										sudo ./setup.sh
									fi
								elif [ "$Discovery" -eq 3 ]
								then
								google-chrome https://urlscan.io/search/# 2>/dev/null
							elif [ "$Discovery" -eq 4 ]
								then
									google-chrome https://dailychanges.domaintools.com/ 2>/dev/null 
								elif [ "$Discovery" -eq 5 ]
									then
										google-chrome https://cloud.gjertsen.net/login 2>/dev/null
									elif [ "$Discovery" -eq 6 ]
										then
											google-chrome https://redirectdetective.com/ 2>/dev/null
										elif [ "$Discovery" -eq 7 ]
											then
												google-chrome https://github.com/digininja/sitediff 2>/dev/null
												firefox https://digi.ninja/projects/sitediff.php 2>/dev/null
											elif [ "$Discovery" -eq 8 ]
												then
												google-chrome https://analyzeid.com/ 2>/dev/null
											fi
										elif [ "$domain" -eq 4 ]
											then
												echo "1. Google's Certificate Transparency"
												echo "2. Spyse"
												echo "3. Censys"
												echo "4. crt.sh - Certificate Search"
												echo "5. Certgraph"
												read -p "Enter your option: " certificate_search
												if [ "$certificate_search" -eq 1 ]
												then
													google-chrome https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md 2>/dev/null
												elif [ "$certificate_search" -eq 2 ]
													then
														google-chrome https://spyse.com/search/certificate 2>/dev/null
													elif [ "$certificate_search" -eq 3 ]
														then
															google-chrome https://censys.io/ 2>/dev/null
														elif [ "$certificate_search" -eq 4 ]
															then
																 google-chrome https://crt.sh/? 2>/dev/null
																elif [ "$certificate_search" -eq 5 ]
																	then
																		google-chrome https://github.com/lanrat/certgraph 2>/dev/null
																		fi
																	elif [ "$domain" -eq 5 ]
																		then
																			echo "1. Security Trails"
																			echo "2. Mnemonic"
																			echo "3. DNS History"
																			echo "4. PTRarchive.com"
																			echo "5. DNS Dumpster"
																			echo "6. Deteque (R)"
																			read -p "Enter your option: " PassiveDNS
																			if [ "$PassiveDNS" -eq 1 ]
																			then
																				google-chrome https://securitytrails.com/ 2>/dev/null
																			elif [ "$PassiveDNS" -eq 2 ]
																				then
																					google-chrome https://passivedns.mnemonic.no/ 2>/dev/null
																				elif [ "$PassiveDNS" -eq 3 ]
																					then
																						google-chrome http://dnshistory.org/ 2>/dev/null
																					elif [ "$PassiveDNS" -eq 4 ]
																						then
																							google-chrome http://ptrarchive.com/ 2>/dev/null
																						elif [ "$PassiveDNS" -eq 5 ]
																							then
																								google-chrome https://dnsdumpster.com/ 2>/dev/null
																							elif [ "$PassiveDNS" -eq 6 ]
																								then
																									google-chrome https://www.spamhaus.com/ 2>/dev/null

																			fi

																		elif [ "$domain" -eq 6 ]
																			then
																				echo "1. UrlQuery.net"
																				echo "2. PassiveTotal"
																				echo "3. URL Void"
																				echo "4. Threat Crowd"
																				echo "5. FortiGuard Reputation Service"
																				echo "6. McAfee Trusted Source"
																				echo "7. Trend Micro Site Safety Center"
																				echo "8. WatchGuard Reputation Authority"
																				echo "9. Sucuri SiteCheck"
																				echo "10. ThreatMiner.org"
																				echo "11. BlueCoat WebPulse"
																				echo "12. Zscalar Zulu URL Risk Analyzer"
																				echo "13. Joe Sandbox URL Analyzer"
																				echo "14. Deepviz Domain Search"
																				echo "15. Cisco SenderBase"
																				echo "16. AVG Threat Labs"
																				echo "17. Webroot BrightCloud URL/IP Lookup"
																				echo "18. vURL online"
																				echo "19. AlienVault Open Threat Exchange"
																				echo "20. Malware Domain List"
																				echo "21. Web Inspector Online Scan"
																				echo "22. Google Safe Browsing API"
																				echo "23. hpHosts Online"
																				read -p "Enter your option: " Reputation
																				if [ "$Reputation" -eq 1 ]
																				then
																					google-chrome http://urlquery.net/ 2>/dev/null
																				elif [ "$Reputation" -eq 2 ]
																					then
																						google-chrome https://community.riskiq.com/ 2>/dev/null
																					elif [ "$Reputation" -eq 3 ]
																						then
																							google-chrome https://www.urlvoid.com/ 2>/dev/null
																						elif [ "$Reputation" -eq 4 ]
																							then
																								google-chrome https://www.threatcrowd.org/ 2>/dev/null
																							elif [ "$Reputation" -eq 5 ]
																								then
																									google-chrome http://fortiguard.com/iprep 2>/dev/null
																								elif [ "$Reputation" -eq 6 ]
																									then
																										google-chrome https://www.trustedsource.org/ 2>/dev/null
																									elif [ "$Reputation" -eq 7 ]
																										then
																											google-chrome https://global.sitesafety.trendmicro.com/ 2>/dev/null
																										elif [ "$Reputation" -eq 8 ]
																											then
																												google-chrome http://www.reputationauthority.org/ 2>/dev/null
																											elif [ "$Reputation" -eq 9 ]
																												then
																													google-chrome https://sitecheck.sucuri.net/ 2>/dev/null
																												elif [ "$Reputation" -eq 10 ]
																													then
																														google-chrome https://www.threatminer.org/ 2>/dev/null
																													elif [ "$Reputation" -eq 11 ]
																														then
																															google-chrome https://sitereview.bluecoat.com/sitereview.jsp 2>/dev/null
																														elif [ "$Reputation" -eq 12 ]
																															then
																																google-chrome http://zulu.zscaler.com/ 2>/dev/null
																															elif [ "$Reputation" -eq 13 ]
																																then
																																	google-chrome https://search.deepviz.com/ 2>/dev/null
																																elif [ "$Reputation" -eq 14 ]
																																	then
																																		google-chrome https://www.url-analyzer.net/ 2>/dev/null
																																	elif [ "$Reputation" -eq 15 ]
																																		then
																																			google-chrome http://www.senderbase.org/ 2>/dev/null
																																		elif [ "$Reputation" -eq 16 ]
																																			then
																																				google-chrome http://www.avgthreatlabs.com/ww-en/website-safety-reports/ 2>/dev/null
																																			elif [ "$Reputation" -eq 17 ]
																																				then
																																					google-chrome http://www.brightcloud.com/tools/url-ip-lookup.php 2>/dev/null
																																				elif [ "$Reputation" -eq 18 ]
																																					then
																																						google-chrome https://vurldissect.co.uk/ 2>/dev/null
																																					elif [ "$Reputation" -eq 19 ]
																																						then
																																							google-chrome https://otx.alienvault.com/browse/pulses/ 2>/dev/null
																																						elif [ "$Reputation" -eq 20 ]
																																							then
																																								google-chrome http://www.malwaredomainlist.com/mdl.php 2>/dev/null
																																							elif [ "$Reputation" -eq 21 ]
																																								then
																																									google-chrome http://app.webinspector.com/ 2>/dev/null
																																								elif [ "$Reputation" -eq 22 ]
																																									then
																																										google-chrome https://developers.google.com/safe-browsing/?csw=1 2>/dev/null
																																									elif [ "$Reputation" -eq 23 ]
																																										then
																																											google-chrome http://hosts-file.net/ 2>/dev/null


																				fi

																			elif [ "$domain" -eq 7 ]
																				then
																					echo "1. Ransomware Tracker Abuse.ch"
																					echo "2. Threatexpert.com Malicious URLs"
																					echo "3. Malware Domains Blackists"
																					echo "4. Blackweb"
																					echo "5. Critical Stack Intel (R)"
																					echo "6. DNS Sinkhole"
																					echo "7. DNS-BH Malware Domain Blackist"
																					echo "8. Malware Patrol (R)"
																					echo "9. MalwareURL (R)"
																					echo "10. scumware.org"
																					echo "11. ZeuS Tracker"
																					echo "12. shadowserver Foundation"
																					echo "13. Email Domain Verification"
																					read -p "Enter your option: " domain_blacklists

																					if [ "$domain_blacklists" -eq 1 ]
																					then
																						google-chrome https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt 2>/dev/null
																					elif [ "$domain_blacklists" -eq 2 ]
																						then
																							google-chrome https://www.networksec.org/grabbho/block.txt 2>/dev/null
																						elif [ "$domain_blacklists" -eq 3 ]
																							then
																								google-chrome https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist 2>/dev/null
																							elif [ "$domain_blacklists" -eq 4 ]
																								then
																									google-chrome http://mirror1.malwaredomains.com/files/domains.txt 2>/dev/null
																								elif [ "$domain_blacklists" -eq 5 ]
																									then 
																										google-chrome https://github.com/maravento/blackweb 2>/dev/null
																									elif [ "$domain_blacklists" -eq 6 ]
																										then
																											google-chrome https://intel.criticalstack.com/ 2>/dev/null
																										elif [ "$domain_blacklists" -eq 7 ]
																											then
																												google-chrome http://malc0de.com/bl/ 2>/dev/null
																											elif [ "$domain_blacklists" -eq 8 ]
																												then
																													google-chrome http://www.malwaredomains.com/wordpress/?page_id=66 2>/dev/null
																												elif [ "$domain_blacklists" -eq 9 ]
																													then
																														google-chrome http://www.malware.com.br/open-source.shtml 2>/dev/null
																													elif [ "$domain_blacklists" -eq 10 ]
																														then
																															google-chrome http://www.malwareurl.com/index.php 2>/dev/null
																														elif [ "$domain_blacklists" -eq 11 ]
																															then
																																google-chrome https://www.scumware.org/ 2>/dev/null
																															elif [ "$domain_blacklists" -eq 12 ]
																																then
																																	google-chrome https://zeustracker.abuse.ch/blocklist.php 2>/dev/null
																																elif [ "$domain_blacklists" -eq 13 ]
																																	then
																																		google-chrome http://www.shadowserver.org/wiki/pmwiki.php?n=Services/Reports 2>/dev/null
																																	elif [ "$domain_blacklists" -eq 14 ]
																																		then
																																			google-chrome https://www.mailboxvalidator.com/domain 2>/dev/null

																					fi

																				elif [ "$domain" -eq 8 ]
																					then
																						echo "1. DNS Twist (T)"
																						echo "2. URLCrazy (T)"
																						echo "3. dnstwister"
																						echo "4. Catphish (T)"
																						read -p "Enter your option: " Typosquatting

																						if [ "$Typosquatting" -eq 1 ]
																						then
																							if [ -d dnstwist ]
																							then
																								echo "If you want you access there online tool"
																								echo "Visit: https://dnstwist.it/"
																								dnstwist -h
																								read -p "Enter Domain: " domain
																								sudo dnstwist --registered $domain
																								sudo dnstwist --registered $domain && sudo dnstwist --ssdeep $domain && sudo dnstwist --mxcheck $domain


																							
																						else
																							echo "For any other OS installation"
																							echo "Visit: https://github.com/elceef/dnstwist"
																							sudo apt-get install dnstwist -y
																							echo "If you want you access there online tool"
																							echo "Visit: https://dnstwist.it/"
																							read -p "Enter Domain: " domain
																							sudo dnstwist --registered $domain && sudo dnstwist --ssdeep $domain && sudo dnstwist --mxcheck $domain
																							
																						fi

																					elif [ "$Typosquatting" -eq 2 ]
																						then
																							sudo apt-get update -y
																							sudo apt-get install urlcrazy
																							read -p "Enter domain: " domain
																							urlcrazy -k dvorak -r $domain
																							echo "If you want you access there online tool"
																							echo "Visit: https://dnstwist.it/"

																						elif [ "$Typosquatting" -eq 3 ]
																						then
																							google-chrome https://dnstwister.report/ 2>/dev/null
																							elif [ "$Typosquatting" -eq 4 ]
																							then
																							 	if [ -d catphish ]
																							 	then
																							 		read -p "Enter domain: " DOMAIN
																							 			echo "Generate all types: \n"
																							 			sudo catphish.rb -D $DOMAIN generate -A
																							 			echo ""
																							 			echo "Check available expired domains: "
																							 			sudo catphish.rb -D $DOMAIN expired
																							 			echo ""
																							 			echo "Check against a specific domain for categorization status: "
																							 			sudo catphish.rb -D DOMAIN expired -c
																							 		else
																							 			sudo git clone https://github.com/ring0lab/catphish.git
																							 			cd catphish && bundle install
																							 			read -p "Enter domain: " DOMAIN
																							 			echo "Generate all types: \n"
																							 			sudo catphish.rb -D $DOMAIN generate -A
																							 			echo ""
																							 			echo "Check available expired domains: "
																							 			sudo catphish.rb -D $DOMAIN expired
																							 			echo ""
																							 			echo "Check against a specific domain for categorization status: "
																							 			sudo catphish.rb -D DOMAIN expired -c

																							 fi

																							elif [ "$domain" -eq 9 ]
																								then
																									echo "1. BuiltWith"
																									echo "2. SiteSleuth"
																									echo "3. Wappalyzer"
																									echo "4. SEMrush"
																									echo "5. Top Gainers"
																									echo "6. Moonsearch"
																									echo "7. StackShare"
																									echo "8. Ewhois"
																									echo "9. Netcraft"
																									echo "10. StatsCrop"
																									echo "11. Open Site Explorer"
																									echo "12. SpyOnWeb"
																									echo "13. SecurityHeaders.io"
																									echo "14. Keyword Density"
																									echo "15. Alexa Site Statistics"
																									echo "16. Cisco Umbrella Popularity List"
																									echo "17. Alexa Top 500 Global Sites"
																									echo "18. W3bin.com"
																									echo "19. Sitedossier"
																									echo "20. Visual Site Mapper"
																									echo "21. ClearWebStats.com"
																									echo "22. PubDB"
																									echo "23. www Domain Tools"
																									echo "24. SimilarWeb"
																									echo "25. Website Outlook"
																									echo "26. Siteliner"
																									echo "27. WebPageTest"
																									echo "28. WhatWeb"

																									read -p "Enter your option: " analytics

																									if [ "$analytics" -eq 1 ]
																									then
																										google-chrome http://builtwith.com/ 2>/dev/null
																									elif [ "$analytics" -eq 2 ]
																										then
																											google-chrome https://www.sitesleuth.io/ 2>/dev/null
																										elif [ "$analytics" -eq 3 ]
																											then
																												google-chrome 


																									fi
																								fi

																						fi


	fi						
				

}

ip_address () {

	echo "1. Geolocation"
	echo "2. Host / Port Discovery"
	echo "3. IPv4"
	echo "4. IPv6"
	echo "5. BGP"
	echo "6. Reputation"
	echo "7. Blackists"
	echo "8. Neighbor Domains"
	echo "9. Protected by Cloud Services"
	echo "10. Wireless Network Info"
	echo "11. Network Analysis Tools"
	echo "12. IP Loggers"


}

images_videos_docs () {

	echo "1. Images"
	echo "2. Videos"
	echo "3. Webcams"
	echo "4. Documents"
	echo "5. Fonts"
}

social_networks () {

	echo "1. Facebook"
	echo "2. Twitter"
	echo "3. Reddit"
	echo "4. LinkedIn"
	echo "5. Other Social Networks"
	echo "6. Social Media Monitoring Wiki"
}

instant_messaging () {

	echo "1. Skype"
	echo "2. Snapchat"
	echo "3. Kik"
	echo "4. Yikyak"
}

people_search_engines () {

	echo "1. General People Search"
	echo "2. Registries"
}

dating () {

	echo "1. Match.com"
	echo "2. AYI.com"
	echo "3. Plenty Of Fish.com"
	echo "4. eHarmony"
	echo "5. Farmers Only"
	echo "6. Zoosk"
	echo "7. okCupid"
	echo "8. Tinder (R)"
	echo "9. Wamba.com"
	echo "10. AdultFriendFinder"
	echo "11. Ashley Madison"
	echo "12. BeautifulPeople.com"
	echo "13. Badoo"
	echo "14. Spark.com"
	echo "15. Meetup"
	echo "16. BlackPeopleMeet"
	echo "17. Reviews of Users"

}

telephone_numbers () {

	echo "1. Voicemail"
	echo "2. International"
	echo "3. Pipl API (M)"
	echo "4. WhoCalid"
	echo "4. 411"
	echo "5. CallerID Test"
	echo "6. ThatsThem - Reverse Phone Lookup"
	echo "7. Twillo Lookup"
	echo "8. Fone Finder"
	echo "9. True Caller"
	echo "10. Reverse Genie"
	echo "11. SpyDialer"
	echo "12. Phone Validator"
	echo "13. Free Carrier Loopup"
	echo "14. Mr. Number (M)"
	echo "15. CallerIDService.com (R)"
	echo "16. Next Caller (R)"
	echo "17. Data24-7 (R)"
	echo "18. HLR Lookup Portal (R)"
	echo "19. OpenCNAM"
	echo "20. OpenCNAM API"
	echo "21. ISPhoneBook"
	echo "22. Numspy"
	echo "23. Numspy-Api"
}

public_records () {

	echo "1. Property Records"
	echo "2. Court / Criminal Records"
	echo "3. Government Records"
	echo "4. Financial / Tax Resources"
	echo "5. Birth Records"
	echo "6. Death Records"
	echo "7. US County Data"
	echo "8. Voter Records"
	echo "9. Patent Records"
	echo "10. Political Records"
	echo "11. Public Records?"
	echo "12. Enigma"
	echo "13. The World Bank Open Data Catalog"
	echo "14. BRB Public Records"
	echo "15. GOVDATA - Das Datenportal fur Deutschland (German)"
	echo "16. Open-Data-Portal Muchen (German)"
}

business_records () {

	echo "1. Annual Reports"
	echo "2. General Info & News"
	echo "3. Company Profiles"
	echo "4. Employee Profiles & Resumes"
	echo "5. Additional Resources"
}

transportation () {

	echo "1. Vehicle Records"
	echo "2. Air Traffic Records"
	echo "3. Marine Records"
	echo "4. Railway Records"
	echo "5. Satellite Tracking"
	echo "6. Track-Trace"
}

geolocation_tools_maps () {

	echo "1. Geolocation Tools"
	echo "2. Coordinates"
	echo "3. Map Reporting Tools"
	echo "4. Mobile Coverage"
	echo "5. Google Maps"
	echo "6. Bing Maps"
	echo "7. HERE Maps"
	echo "8. Dual Maps"
	echo "9. Instant Google Street View"
	echo "10. Wikimapia"
	echo "11. OpenStreetMap"
	echo "12. Flash Earth"
	echo "13. Historic Aerials"
	echo "14. Google Maps Update Alerts"
	echo "15. Google Earth Overlays"
	echo "16. Yandex.Maps"
	echo "17. TerraServer"
	echo "18. Google Earth"
	echo "19. Baidu Maps"
	echo "20. Corona"
	echo "21. Daum (Korean)"
	echo "22. Naver (Korean)"
	echo "23. OpenStreetMap"
	echo "24. EarthExplorer"
	echo "25. OpenStreetCam"
	echo "26. Dronetheworld"
	echo "27. Travel By Drone"
	echo "28. Hivemapper"
	echo "29. Landsatlook Viewer"
	echo "30. Sentinel2Look Viewer"
	echo "31. NEXRAD Data Inventory Search"
	echo "32. MapQuest"
	echo "33. OpenRailwayMap"
	echo "34. OpenStreetMap Routing Service"
	echo "35. Hiking & Biking Map"
	echo "35. US Nav Guide Xip Code Data"
	echo "36. Wayback Imagery"
}

search_engines () {

	echo "1. General Search"
	echo "2. Meta Search"
	echo "3. Code Search"
	echo "4. FTP Search"
	echo "5. Academic / Publication Search"
	echo "6. News Search"
	echo "7. Other Search"
	echo "8. Search Engine Guides"
	echo "9. Fact Checking"
}

forums_blogs_IRC () {

	echo "1. Forum Search Engines"
	echo "2. Blog Search Engines"
	echo "3. IRC Search"

}

archives () {

	echo "1. Web"
	echo "2. Data Leaks"
	echo "3. Public Datasets"
	echo "4. Other Media"
}

language_translation () {

	echo "1. Text"
	echo "2. Pictures"
	echo "3. Anaylsis"

}

metadata () {

	echo "1. ExifTool (T)"
	echo "2. Metagoofil (T)"
	echo "3. FOCA (T)"
	echo "4. CodeTwo Outlook Export (T)"
	read -p "Enter your option: " metadata
	if [ "$metadata" -eq 1 ]
	then
		google-chrome https://exiftool.org/ 2>/dev/null
	elif [ "$metadata" -eq 2 ]
		then
			google-chrome http://www.edge-security.com/metagoofil.php 2>/dev/null
		elif [ "$metadata" -eq 3 ]
			then
				google-chrome https://www.elevenpaths.com/innovation-labs/technologies/foca 2>/dev/null
		elif [ "$metadata" -eq 4 ]
			then
				google-chrome https://www.codetwo.com/freeware/outlook-export/ 2>/dev/null

	fi
}

mobile_emulation () {

	echo "1. Android"
	echo "2. Emulation Tools"
	echo "3. Apps"
	read -p "Enter your option: " android
	if [ "$android" -eq 1 ]
	then
		echo "1. Genymotion (T)"
		echo "2. BlueStacks 2 (T)"
		echo "3. Andy Android Emulator (T)"
		echo "4. Nox App Player"
		read -p "Enter your option: " emulation
		if [ "$emulation" -eq 1 ]
		then
			google-chrome https://www.genymotion.com/download/
		elif [ "$emulation" -eq 2 ]
			then
				google-chrome http://www.bluestacks.com/
			elif [ "$emulation" -eq 3 ]
				then
					google-chrome http://www.andyroid.net/
				elif [ "$emulation" -eq 4 ]
					then
						google-chrome https://www.bignox.com/

		fi

	elif [ "$android" -eq 2 ]
		then
			echo "1. Social Networking"
			echo "2. Instant Messaging"
			echo "3. Pictures"
			echo "4. Streaming Video"
			echo "5. Truecaller (T)"
			read -p "Enter your option: " apps
			if [ "$apps" -eq 1 ]
			then
				 echo "1. Facebook (T)"
				 echo "2. LinkedIn (T)"
				 echo "3. Twitter (T)"
				 echo "4. Pinterest (T)"
				 read -p "Enter your option" social_Networking
				 if [ "$social_Networking" -eq 1 ]
				 then
				 	 google-chrome https://play.google.com/store/apps/details?id=com.facebook.katana 2>/dev/null
				 	elif [ "$social_Networking" -eq 2 ]
				 		then
				 			google-chrome https://play.google.com/store/apps/details?id=com.linkedin.android 2>/dev/null
				 		elif [ "$social_Networking" -eq 3 ]
				 			then
				 				google-chrome https://play.google.com/store/apps/details?id=com.twitter.android 2>/dev/null
				 			elif [ "$social_Networking" -eq 4 ]
				 				then
				 					google-chrome https://play.google.com/store/apps/details?id=com.pinterest 2>/dev/null


				 fi

				elif [ "$apps" -eq 2 ]
					then
						echo "1. Signal Private Messenger (T)"
						echo "2. Tiot.im - Communicate, your way (T)"
						echo "3. Telegram (T)"
						echo "4. Snapchat (T)"
						echo "5. WhatsApp Messenger (T)"
						echo "6. Kik (T)"
						echo "7. Yik Yak (T)"
						echo "8. LINE (T)"
						read -p "Enter your option: " instant_messaging
						if [ "$instant_messaging" -eq 1 ]
						then
							google-chrome https://play.google.com/store/apps/details?id=org.thoughtcrime.securesms 2>/dev/null
						elif [ "$instant_messaging" -eq 2 ]
							then
								google-chrome https://play.google.com/store/apps/details?id=im.vector.app 2>/dev/null
							elif [ "$instant_messaging" -eq 3 ]
								then
									google-chrome https://play.google.com/store/apps/details?id=org.telegram.messenger 2>/dev/null
								elif [ "$instant_messaging" -eq 4 ]
									then
										google-chrome https://play.google.com/store/apps/details?id=org.telegram.messenger 2>/dev/null
									elif [ "$instant_messaging" -eq 5 ]
										then
											google-chrome https://play.google.com/store/apps/details?id=com.whatsapp 2>/dev/null
										elif [ "$instant_messaging" -eq 6 ]
											then
												google-chrome https://play.google.com/store/apps/details?id=kik.android 2>/dev/null
											elif [ "$instant_messaging" -eq 7 ]
												then
													google-chrome https://play.google.com/store/apps/details?id=com.yik.yak 2>/dev/null
												elif [ "$instant_messaging" -eq 8 ]
													then
														google-chrome https://play.google.com/store/apps/details?id=jp.naver.line.android 2>/dev/null


						fi

					elif [ "$apps" -eq 3 ]
						then
							echo "1. Instagram (T)"
							echo "2. Flickr (T)"
							read -p "Enter your option: " pictures
							if [ "$pictures" -eq 1 ]
							then
								google-chrome https://play.google.com/store/apps/details?id=com.instagram.android 2>/dev/null
							elif [ "$pictures" -eq 2 ]
								then
									google-chrome https://play.google.com/store/apps/details?id=com.yahoo.mobile.client.android.flickr 2>/dev/null

							fi

						elif [ "$apps" -eq 4 ]
							then
								echo "1. Periscope (T)"
								echo "2. Meerkat (T)"
								echo "3. Vine (T)"
								read -p "Enter your option: " streaming_videos
								if [ "$streaming_videos" -eq 1 ]
								then
									google-chrome https://play.google.com/store/apps/details?id=tv.periscope.android 2>/dev/null
								elif [ "$streaming_videos" -eq 2 ]
									then
										google-chrome https://play.google.com/store/apps/details?id=co.getair.meerkat 2>/dev/null
									elif [ "$streaming_videos" -eq 3 ]
										then
											google-chrome https://play.google.com/store/apps/details?id=co.vine.android 2>/dev/null

								fi

							elif [ "$apps" -eq 5 ]
								then
									google-chrome https://play.google.com/store/apps/details?id=com.truecaller 2>/dev/null

			fi

	fi

}

terrorism () {

	echo "1. Global Terrorism Database"
	google-chrome https://www.start.umd.edu/gtd/  2>/dev/null
}

dark_web () {

	echo "1. General Info"
	echo "2. Clients"
	echo "3. Discovery"
	echo "4. TOR Search"
	echo "5. TOR Directories"
	echo "6. Tor2Web"
	echo "7. Web O Proxy"
	echo "8. IACA Dark Web Investigation Support"
	read -p "Enter your option: " darkweb
	if [ "$darkweb" -eq 1 ]
	then
		echo "1. Reddit Deep Web"
		echo "2. Reddit Onions"
		echo "3. Reddit Darknet"
		read -p "Enter your option: " general_info
		if [ "$general_info" -eq 1 ]
		then
			google-chrome https://www.reddit.com/r/deepweb 2>/dev/null
		elif [ "$general_info" -eq 2 ]
			then
				google-chrome https://www.reddit.com/r/onions 2>/dev/null
			elif [ "$general_info" -eq 3 ]
				then
					google-chrome https://www.reddit.com/r/darknet 2>/dev/null
				fi
			elif [ "$darkweb" -eq 2 ]
				then
					echo "1. Tor Download (T)"
					echo "2. i2P Anonymous Network (T)"
					read -p "Enter your option: " clients
					if [ "$clients" -eq 1 ]
					then
						google-chrome https://www.torproject.org/download/download-easy.html.en 2>/dev/null
					elif [ "$clients" -eq 2 ]
						then
							google-chrome https://geti2p.net/en/ 2>/dev/null
						fi

					elif [ "$darkweb" -eq 3 ]
						then
							echo "1. Onion Scan"
							echo "2. TorBot"
							echo "3. Tor Scan"
							echo "4. Onionoff"
							echo "5. Hunchly Hideen Services Report"
							echo "6. docker-onion-nmap (T)"
							echo "7. Onion Investigator"
							read -p "Enter your option: " Discovery
							if [ "$Discovery" -eq 1 ]
							then
								google-chrome https://github.com/s-rah/onionscan 2>/dev/null
							elif [ "$Discovery" -eq 2 ]
								then
									google-chrome https://github.com/DedSecInside/TorBot 2>/dev/null
								elif [ "$Discovery" -eq 3 ] 
									then
										google-chrome http://www.torscan.io/ 2>/dev/null
									elif [ "$Discovery" -eq 4 ]
										then
											google-chrome https://github.com/k4m4/onioff 2>/dev/null
										elif [ "$Discovery" -eq 5 ]
											then
												google-chrome https://darkweb.hunch.ly/ 2>/dev/null
											elif [ "$Discovery" -eq 6 ]
												then
													google-chrome https://github.com/milesrichardson/docker-onion-nmap 2>/dev/null
												elif [ "$Discovery" -eq 7 ]
													then
														google-chrome https://oint.ctrlbox.com/ 2>/dev/null


							fi

						elif [ "$darkweb" -eq 4 ]
							then
								echo "1. Onion Cab"
								echo "2. OnionLink"
								echo "3. Candle"
								echo "4. Not Evil"
								echo "5. Tor66"
								echo "6. Dark.fail"
								echo "7. Ahmia"
								read -p "Enter your opton: " tor_search

								if [ "$tor_search" -eq 1 ]
								then
									google-chrome https://onion.cab/ 2>/dev/null
								elif [ "$tor_search" -eq 2 ]
									then
										google-chrome http://www.onion.link/ 2>/dev/null
									elif [ "$tor_search" -eq 3 ]
										then
											google-chrome http://gjobqjj7wyczbqie.onion/ 2>/dev/null
										elif [ "$tor_search" -eq 4 ]
											then
												google-chrome http://hss3uro2hsxfogfq.onion/ 2>/dev/null
											elif [ "$tor_search" -eq 5 ]
												then
													google-chrome http://tor66sezptuu2nta.onion/ 2>/dev/null
												elif [ "$tor_search" -eq 6 ]
													then
														google-chrome http://darkfailllnkf4vf.onion/ 2>/dev/null
													elif [ "$tor_search" -eq 7 ]
														then
															google-chrome https://ahmia.fi/ 2>/dev/null

														fi
													elif [ "$darkweb" -eq 5 ]
														then
															echo "1. Hidden Wiki"
															echo "2. Core.onion"
															echo "3. OnionTree"
															read -p "Enter your option: " TOR_directories

															if [ "$TOR_directories" -eq 1 ]
															then
																google-chrome http://thehiddenwiki.org/ 2>/dev/null
															elif [ "$TOR_directories" -eq 2 ]
																then
																	google-chrome http://eqt5g4fuenphqinx.onion/ 2>/dev/null
																elif [ "$TOR_directories" -eq 3 ]
																	then
																		google-chrome https://onionltd.github.io/ 2>/dev/null
																	fi

																elif [ "$darkweb" -eq 6 ]
																	then
																		google-chrome https://tor2web.org/ 2>/dev/null
																	elif [ "$darkweb" -eq 7 ]
																		then
																			google-chrome https://weboproxy.com/ 2>/dev/null
																		elif [ "$darkweb" -eq 8 ]
																			then
																				google-chrome https://iaca-darkweb-tools.com/ 2>/dev/null






	fi
}

digital_currency () {

	echo "1. Bitcoin"
	echo "2. Ethereum"
	echo "3. Monero"
	

}

classifieds () {

echo "1. Craigslist"
echo "2. Kijiji - Canada Classfieds"
echo "3. Quikr - India Classfieds"
echo "4. eBay"
echo "5. OfferUp"
echo "6. Goofbid"
echo "7. Flippity"
echo "8. SearchAllJunk"
echo "9. TotalCraigSearch"
echo "10. Backpage"
echo "11. Search Tempest"
echo "12. Oodle"
echo "Claz.org"

}

encoding_decoding () {

	echo "1. Base64"
	echo "2. Barcodes / QR"
	echo "3. Javascript"
	echo "4. PHP"
	echo "5. XOR"
	echo "6. CyberChef"
	echo "7, Functions Online"
}

tools () {

echo "1. OSINT Automation"
echo "2. Pentesting Recon"
echo "3. Virtual Machines"
echo "4. Paterva / Maltego (T)"
echo "5. Epic Privacy Browser (T)"
echo "6. Overview"

}

malicious_file_analysis () {

	echo "1. Search"
	echo "2. Hosted Automated Anaylsis"
	echo "3. Office Files"
	echo "4. PDFs"
	echo "5. PCAPs"
	echo "6. Ghidra (T)"
	echo "7. Malware Analysis Tools"
}

exploits_advisories () {

	echo "1. Default Passwords"
	echo "2. MITRE ATT&CK"
	echo "3. Exploit DB"
	echo "4. Packet Storm"
	echo "5. SecurityFocus"
	echo "6. NVD - NIST"
	echo "7. OSVDB: Open Sourced Vulnerability Database"
	echo "8. CVE Details"
	echo "9. OWASP"
	echo "10. 0day.today"
	echo "11. Secunia"
	echo "12. Canadian Centre for Cyber Security"
	read -p "Enter your option: " exploits_advisories
	if [ "$exploits_advisories" -eq 1 ]
	then
		echo "1. Default Passwords DB"
		echo "2. Default Passwords list"
		echo "3. Default Passwords Lookup Utility"
		echo "4. Phenoelit Default Password List"
		echo "5. Open Sez Me Default Passwords"
		echo "6. Hashes.org"
		read -p "Enter your option: " default_passwords
		if [ "$default_passwords" -eq 1 ]
		then
			google-chrome https://cirt.net/passwords 2>/dev/null
		elif [ "$default_passwords" -eq 2 ]
			then
				google-chrome https://default-password.info/ 2>/dev/null
			elif [ "$default_passwords" -eq 3 ]
				then
					google-chrome http://www.fortypoundhead.com/tools_dpw.asp 2>/dev/null
				elif [ "$default_passwords" -eq 4 ]
					then
						google-chrome http://phenoelit.org/dpl/dpl.html 2>/dev/null
					elif [ "$default_passwords" -eq 5 ]
						then
							google-chrome http://routerpasswords.com/ 2>/dev/null
						elif [ "$default_passwords" -eq 6 ]
							then
								google-chrome https://hashes.org/ 2>/dev/null
		fi

	elif [ "$exploits_advisories" -eq 1 ]
		then
			google-chrome https://attack.mitre.org/ 2>/dev/null
		elif [ "$exploits_advisories" -eq 2 ]
			then
				google-chrome https://www.exploit-db.com/ 2>/dev/null
			elif [ "$exploits_advisories" -eq 3 ]
				then
					google-chrome https://packetstormsecurity.com/ 2>/dev/null
				elif [ "$google-chrome" -eq 4 ]
					then
						google-chrome http://www.securityfocus.com/bid 2>/dev/null
					elif [ "$default_passwords" -eq 5 ]
						then
							google-chrome https://nvd.nist.gov/ 2>/dev/null
						elif [ "$default_passwords" -eq 6 ]
							then
								google-chrome http://osvdb.org/ 2>/dev/null
							elif [ "$default_passwords" -eq 7 ]
								then
									google-chrome http://www.cvedetails.com/ 2>/dev/null
								elif [ "$default_passwords" -eq 8 ]
									then
										google-chrome http://cve.mitre.org/ 2>/dev/null
									elif [ "$default_passwords" -eq 9 ]
										then
											google-chrome https://www.owasp.org/index.php/Main_Page 2>/dev/null
										elif [ "$default_passwords" -eq 10 ]
											then
												google-chrome http://0day.today/ 2>/dev/null
											elif [ "$default_passwords" -eq 11 ]
												then
													google-chrome https://secuniaresearch.flexerasoftware.com/community/research/ 2>/dev/null
												elif [ "$default_passwords" -eq 12 ]
													then
														google-chrome https://cyber.gc.ca/ 2>/dev/null


	fi
}

threat_intelligence () {

	echo "1. Phishing"
	echo "2. IOC Tools"
	echo "3. TTPs"
	echo "4. IBM X-Force Exchange"
	echo "5. Malware Information Sharing Platform"
	echo "6. Project Honey Pot"
	echo "7. Cymon Open Threat Intelligence"
	echo "8. Mlsecproject / combine"
	echo "9. hostintel - keithjjones Github"
	echo "10. massive-octo-spice - csirtgadgets Github"
	echo "11. Bot Scout"
	echo "12. Blueliv Threat Exchange (R)"
	echo "13. APTnotes"
	echo "14. HoneyDB"
	echo "15. Pulsedive"
	echo "16. Mr. Looquer IOC Feed - 1st Dual Stack Threat Feed"
}

Opsec () {

	echo "1. Persona Creation"
	echo "2. Anonymous Browsing"
	echo "3. Privacy / Clean Up"
	echo "4. Metadata / Style"
}

documentation () {

	echo "1. Web Browsing"
	echo "2. Screen Capture"
	echo "3. Map Locations"
	echo "4. Timelines JS3"
	read -p "Enter your option: " documentation
	if [ "$documentation" -eq 1 ]
	then
		echo "1. Hunchly (T)"
		echo "2. Fiddler (T)"
		echo "3. Burp Suite (T)"
		echo "4. Page2Images (T)"
		echo "5. Archive.is"
		echo "6. Web Page Saver"
		echo "7. Snapper (T)"
		echo "8. Full Page Screen Capture Chrome Extension (T)"
		read -p "Enter your option: " web_browsing
		if [ "$web_browsing" -eq 1 ]
		then
			google-chrome http://www.hunch.ly/ 2>/dev/null
		elif [ "$web_browsing" -eq 2 ]
			then
				google-chrome https://www.telerik.com/download/fiddler 2>/dev/null
			elif [ "$web_browsing" -eq 3 ]
				then
					google-chrome https://portswigger.net/burp/download.html 2>/dev/null
				elif [ "$web_browsing" -eq 4 ]
					then
						google-chrome http://www.page2images.com/URL-Live-Website-Screenshot-Generator 2>/dev/null
					elif [ "$web_browsing" -eq 5 ]
						then
							google-chrome https://archive.is/ 2>/dev/null
						elif [ "$web_browsing" -eq 6 ]
							then
								google-chrome https://www.magnetforensics.com/resources/web-page-saver// 2>/dev/null
							elif [ "$web_browsing" -eq 7 ]
								then
									echo "This is an optional tool to install"
									echo -n "But if you wish you can visit: "
									echo "https://github.com/dxa4481/Snapper"
								elif [ "$web_browsing" -eq 8 ]
									then
										google-chrome https://github.com/mrcoles/full-page-screen-capture-chrome-extension 2>/dev/null


		fi

	elif [ "$documentation" -eq 2 ]
		then
			echo "1. FRAPS (T)"
			echo "2. ShareX (T)"
			echo "3. Grenshot (T)"
			read -p "Enter your option: " screen_capture

			if [ "$screen_capture" -eq 1 ]
			then
				google-chrome https://fraps.com/ 2>/dev/null
			elif [ "$screen_capture" -eq 2 ]
				then
					google-chrome https://getsharex.com/ 2>/dev/null
				elif [ "$screen_capture" -eq 3 ]
					then
						google-chrome https://getgreenshot.org/ 2>/dev/null

			fi

		elif [ "$documentation" -eq 3 ]
			then
				echo "1. Batch Geo"
				echo "2. Google Street View - Hyperlapse"
				echo "3. Teehan+Lax Labs - Hyperlapse"
				echo "4. Google Maps StreetView Player"
				echo "5. ZeeMaps"
				read -p "Enter your option: " map_locations
				if [ "$map_locations" -eq 1 ]
				then
					google-chrome https://batchgeo.com/ 2>/dev/null
				elif [ "$map_locations" -eq 2 ]
					then
						google-chrome https://github.com/TeehanLax/Hyperlapse.js.git 2>/dev/null
					elif [ "$map_locations" -eq 3 ]
						then
							google-chrome http://labs.teehanlax.com/project/hyperlapse 2>/dev/null
						elif [ "$map_locations" -eq 4 ]
							then
								google-chrome http://brianfolts.com/driver/ 2>/dev/null
							elif [ "$map_locations" -eq 5 ]
								then
									google-chrome https://www.zeemaps.com/2>/dev/null

				fi

			elif [ "$documentation" -eq 4 ]
				then
					google-chrome http://timeline.knightlab.com/2>/dev/null

	fi
}

training () {

	echo "1. Games"
	echo "2. AutomatingOSINT.com"
	echo "3. Open Source Intelligence Techniques"
	echo "4. Plessas"
	echo "5. SANS SEC487 OSINT Class"
	echo "6. NetBootCamp"
	echo "7. Smart Questions"
	read -p "Enter your option: " training

	if [ "$training" -eq 1 ]
	then
		echo "1. A Google A Day"
		echo "2. GeoGuesser"
		echo "3. Verification Quiz Bot"
		read -p "Enter your option: " games
		if [ "$games" -eq 1 ]
		then
			google-chrome http://www.agoogleaday.com/ 2>/dev/null
		elif [ "$games" -eq 2 ]
			then
				google-chrome https://geoguessr.com/ 2>/dev/null
			elif [ "$games" -eq 3 ]
				then
					google-chrome https://twitter.com/quiztime 2>/dev/null
		fi
	elif [ "$games" -eq 2 ]
		then
			google-chrome https://register.automatingosint.com/ 2>/dev/null
		elif [ "$games" -eq 3 ]
			then
				google-chrome https://inteltechniques.com/ 2>/dev/null
			elif [ "$games" -eq 4 ]
				then
					google-chrome https://plessas.net/online-training 2>/dev/null
				elif [ "$games" -eq 5 ]
					then
						google-chrome https://www.sans.org/cyber-security-courses/open-source-intelligence-gathering/ 2>/dev/null
					elif [ "$games" -eq 6 ]
						then
							google-chrome http://netbootcamp.org/ 2>/dev/null
						elif [ "$games" -eq 7 ]
							then
								google-chrome http://www.catb.org/esr/faqs/smart-questions.html 2>/dev/null

	fi
}
 
	starting

if [ "$choice" -eq 1 ]
then
	username
elif [ "$choice" -eq 2 ]
	then
		email_address
elif [ "$choice" -eq 3 ]
	then
		domain_name
	elif [ "$choice" -eq 4 ]
		then
			ip_address
		elif [ "$choice " -eq 5 ]
			then
				images_videos_docs
			elif [ "$choice" -eq 6 ]
				then
					social_networks
				elif [ "$choice" -eq 7 ]
					then
						instant_messaging
					elif [ "$choice" -eq 8 ]
						then
							people_search_engines
						elif [ "$choice" -eq 9 ]
							then
								dating
							elif [ "$choice" -eq 10 ]
								then
									telephone_numbers
								elif [ "$choice" -eq 11 ]
									then
										public_records
									elif [ "$choice" -eq 12 ]
										then
											business_records
										elif [ "$choice" -eq 13 ]
											then
												transportation
											elif [ "$choice" -eq 14 ]
												then
													geolocation_tools_maps
												elif [ "$choice" -eq 15 ]
													then
														search_engines
													elif [ "$choice" -eq 16 ]
														then
															forums_blogs_IRC
														elif [ "$choice" -eq 17 ]
															then
																archives
															elif [ "$choice" -eq 18 ]
																then
																	language_translation
																elif [ "$choice" -eq 19 ]
																	then
																		metadata
																	elif [ "$choice" -eq 20 ]
																		then
																			mobile_emulation
																		elif [ "$choice" -eq 21 ]
																			then
																				terrorism
																			elif [ "$choice" -eq 22 ]
																				then
																					dark_web
																				elif [ "$choice" -eq 23 ]
																					then
																						digital_currency
																					elif [ "$choice" -eq 24 ]
																						then
																							classifieds
																						elif [ "$choice" -eq 25 ]
																							then
																								encoding_decoding
																							elif [ "$choice" -eq 26 ]
																								then
																									tools
																								elif [ "$choice" -eq 27 ]
																									then
																										malicious_file_analysis
																									elif [ "$choice" -eq 28 ]
																										then
																											exploits_advisories
																										elif [ "$choice" -eq 29 ]
																											then
																												threat_intelligence
																											elif [ "$choice" -eq 30 ]
																												then
																													Opsec
																												elif [ "$choice" -eq 31 ]
																													then
																														documentation
																													elif [ "$choice" -eq 32 ]
																														then
																															training

																														fi
