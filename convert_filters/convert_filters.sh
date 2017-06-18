#!/bin/bash

function echo_color(){
	local text="${2}" 
	case ${1} in
		0 ) echo -e "\033[40m\033[30m${text}\033[0m";;
		1 ) echo -e "\033[40m\033[1;30m${text}\033[0m";;
		2 ) echo -e "\033[40m\033[31m${text}\033[0m";;
		3 ) echo -e "\033[40m\033[1;31m${text}\033[0m";;
		4 ) echo -e "\033[40m\033[32m${text}\033[0m";;
		5 ) echo -e "\033[40m\033[1;32m${text}\033[0m";;
		6 ) echo -e "\033[40m\033[33m${text}\033[0m";;
		7 ) echo -e "\033[40m\033[1;33m${text}\033[0m";;
		8 ) echo -e "\033[40m\033[34m${text}\033[0m";;
		9 ) echo -e "\033[40m\033[1;34m${text}\033[0m";;
		10 ) echo -e "\033[40m\033[35m${text}\033[0m";;
		11 ) echo -e "\033[40m\033[1;35m${text}\033[0m";;
		12 ) echo -e "\033[40m\033[36m${text}\033[0m";;
		13 ) echo -e "\033[40m\033[1;36m${text}\033[0m";;
		14 ) echo -e "\033[40m\033[37m${text}\033[0m";;
		15 ) echo -e "\033[40m\033[1;37m${text}\033[0m";;
		20 ) echo -e "\033[47m\033[30m${text}\033[0m";;
		21 ) echo -e "\033[47m\033[1;30m${text}\033[0m";;
		22 ) echo -e "\033[47m\033[31m${text}\033[0m";;
		23 ) echo -e "\033[47m\033[1;31m${text}\033[0m";;
		24 ) echo -e "\033[47m\033[32m${text}\033[0m";;
		25 ) echo -e "\033[47m\033[1;32m${text}\033[0m";;
		26 ) echo -e "\033[47m\033[33m${text}\033[0m";;
		27 ) echo -e "\033[47m\033[1;33m${text}\033[0m";;
		28 ) echo -e "\033[47m\033[34m${text}\033[0m";;
		29 ) echo -e "\033[47m\033[1;34m${text}\033[0m";;
		30 ) echo -e "\033[47m\033[35m${text}\033[0m";;
		31 ) echo -e "\033[47m\033[1;35m${text}\033[0m";;
		32 ) echo -e "\033[47m\033[36m${text}\033[0m";;
		33 ) echo -e "\033[47m\033[1;36m${text}\033[0m";;
		34 ) echo -e "\033[47m\033[37m${text}\033[0m";;
		35 ) echo -e "\033[47m\033[1;37m${text}\033[0m";;
	esac
}


function wildcard(){
	local network=`echo ${2} | awk -F'/' '{print $1}'`
	local mask=`echo ${2} | awk -F'/' '{print $2}'`
	if [ "${network}" == "any" ]; then
		echo "any"
	elif [ "${mask}" == "" ]; then
		echo "host ${2}"
	elif [ "${1}" == "ip" ]; then
		case ${mask} in 
			32 ) echo "host ${network}";;
			30 ) echo "${network} 0.0.0.3";;
			29 ) echo "${network} 0.0.0.7";;
			28 ) echo "${network} 0.0.0.15";;
			27 ) echo "${network} 0.0.0.31";;
			26 ) echo "${network} 0.0.0.63";;
			25 ) echo "${network} 0.0.0.127";;
			24 ) echo "${network} 0.0.0.255";;
			23 ) echo "${network} 0.0.1.255";;
			22 ) echo "${network} 0.0.3.255";;
			21 ) echo "${network} 0.0.7.255";;
			20 ) echo "${network} 0.0.15.255";;
			19 ) echo "${network} 0.0.31.255";;
			18 ) echo "${network} 0.0.63.255";;
			17 ) echo "${network} 0.0.127.255";;
			16 ) echo "${network} 0.0.255.255";;
			15 ) echo "${network} 0.1.255.255";;
			14 ) echo "${network} 0.3.255.255";;
			13 ) echo "${network} 0.7.255.255";;
			12 ) echo "${network} 0.15.255.255";;
			11 ) echo "${network} 0.31.255.255";;
			10 ) echo "${network} 0.63.255.255";;
			9 ) echo "${network} 0.127.255.255";;
			8 ) echo "${network} 0.255.255.255";;
			7 ) echo "${network} 1.255.255.255";;
			6 ) echo "${network} 3.255.255.255";;
			5 ) echo "${network} 7.255.255.255";;
			4 ) echo "${network} 15.255.255.255";;
			3 ) echo "${network} 31.255.255.255";;
			2 ) echo "${network} 63.255.255.255";;
			1 ) echo "${network} 127.255.255.255";;
		esac
	elif [ "${1}" == "ipv6" ]; then
		case ${mask} in 
			128 ) echo "host ${network}";;
			* ) echo "${2}"
		esac
	fi
}


function niemonic_rtx(){
	local proto=${1}
	local port=${2}
	if [ "${proto}" == "tcp" ] || [ "${proto}" == "udp" ]; then
		if [ "${proto}" == "tcp" ]; then
			protocol="tcp"
			case ${port} in
				tcpmux ) port_num="1" ;;
				rje ) port_num="5" ;;
				echo ) port_num="7" ;;
				discard ) port_num="9" ;;
				systat ) port_num="11" ;;
				daytime ) port_num="13" ;;
				chargen ) port_num="19" ;;
				ftpdata ) port_num="20" ;;
				ftp ) port_num="20,21" ;;
				telnet ) port_num="23" ;;
				smtp ) port_num="25" ;;
				time ) port_num="37" ;;
				nameserver ) port_num="42" ;;
				whois ) port_num="43" ;;
				auditd ) port_num="48" ;;
				domain ) port_num="53" ;;
				tacacs_ds ) port_num="65" ;;
				dhcps ) port_num="67" ;;
				dhcpc ) port_num="68" ;;
				tftp ) port_num="69" ;;
				gopher ) port_num="70" ;;
				finger ) port_num="79" ;;
				www ) port_num="80" ;;
				kerberos ) port_num="88" ;;
				tcp ) pop2 port_num="109" ;;
				tcp ) pop3 port_num="110" ;;
				sunrpc ) port_num="111" ;;
				ident ) port_num="113" ;;
				nntp ) port_num="119" ;;
				ntp ) port_num="123" ;;
				netbios_ns ) port_num="137" ;;
				netbios_dgm ) port_num="138" ;;
				netbios_ssn ) port_num="139" ;;
				imap2 ) port_num="143" ;;
				snmp ) port_num="161" ;;
				snmptrap ) port_num="162" ;;
				bgp ) port_num="179" ;;
				irc ) port_num="194" ;;
				at_rtmp ) port_num="201" ;;
				at_nbp ) port_num="202" ;;
				at_3 ) port_num="203" ;;
				at_echo ) port_num="204" ;;
				at_5 ) port_num="205" ;;
				at_zis ) port_num="206" ;;
				at_7 ) port_num="207" ;;
				at_8 ) port_num="208" ;;
				imap3 ) port_num="220" ;;
				ldap ) port_num="389" ;;
				netware_ip ) port_num="396" ;;
				timbuktu ) port_num="407" ;;
				mobileip_agent ) port_num="434" ;;
				mobilip_mn ) port_num="435" ;;
				https ) port_num="443" ;;
				exec ) port_num="512" ;;
				login ) port_num="513" ;;
				tcp ) printer port_num="515" ;;
				talk ) port_num="517" ;;
				uucp ) port_num="540" ;;
				submission ) port_num="587" ;;
				doom ) port_num="666" ;;
				* ) port_num=`echo ${port} | egrep '[0-9]{1,5}'` ;;
			esac
		elif [ "${proto}" == "udp" ]; then
			protocol="udp"
			case ${port} in
				tcpmux ) port_num="1" ;;
				rje ) port_num="5" ;;
				echo ) port_num="7" ;;
				discard ) port_num="9" ;;
				systat ) port_num="11" ;;
				daytime ) port_num="13" ;;
				chargen ) port_num="19" ;;
				ftpdata ) port_num="20" ;;
				ftp ) port_num="20,21" ;;
				telnet ) port_num="23" ;;
				smtp ) port_num="25" ;;
				time ) port_num="37" ;;
				nameserver ) port_num="42" ;;
				whois ) port_num="43" ;;
				auditd ) port_num="48" ;;
				domain ) port_num="53" ;;
				tacacs_ds ) port_num="65" ;;
				dhcps ) port_num="67" ;;
				dhcpc ) port_num="68" ;;
				tftp ) port_num="69" ;;
				gopher ) port_num="70" ;;
				www ) port_num="80" ;;
				kerberos ) port_num="88" ;;
				udp ) pop2 port_num="109" ;;
				udp ) pop3 port_num="110" ;;
				sunrpc ) port_num="111" ;;
				ident ) port_num="113" ;;
				nntp ) port_num="119" ;;
				ntp ) port_num="123" ;;
				netbios_ns ) port_num="137" ;;
				netbios_dgm ) port_num="138" ;;
				netbios_ssn ) port_num="139" ;;
				imap2 ) port_num="143" ;;
				snmp ) port_num="161" ;;
				snmptrap ) port_num="162" ;;
				bgp ) port_num="179" ;;
				irc ) port_num="194" ;;
				at_rtmp ) port_num="201" ;;
				at_nbp ) port_num="202" ;;
				at_3 ) port_num="203" ;;
				at_echo ) port_num="204" ;;
				at_5 ) port_num="205" ;;
				at_zis ) port_num="206" ;;
				at_7 ) port_num="207" ;;
				at_8 ) port_num="208" ;;
				imap3 ) port_num="220" ;;
				ldap ) port_num="389" ;;
				netware_ip ) port_num="396" ;;
				timbuktu ) port_num="407" ;;
				mobileip_agent ) port_num="434" ;;
				mobilip_mn ) port_num="435" ;;
				https ) port_num="443" ;;
				biff ) port_num="512" ;;
				who ) port_num="513" ;;
				syslog ) port_num="514" ;;
				udp ) printer port_num="515" ;;
				talk ) port_num="517" ;;
				route ) port_num="520" ;;
				uucp ) port_num="540" ;;
				submission ) port_num="587" ;;
				doom ) port_num="666" ;;
				* ) port_num=`echo ${port} | egrep '[0-9]{1,5}'` ;;
			esac
		fi
	else
		port_num="-"
		case ${proto} in
			icmp ) protocol="1" ;;
			ipv6 ) protocol="41" ;;
			rsvp ) protocol="46" ;;
			gre ) protocol="47" ;;
			esp ) protocol="50" ;;
			ah ) protocol="51" ;;
			icmp6 ) protocol="58" ;;
			ipmpv6 ) protocol="58" ;;
			ping6 ) protocol="58" ;;
			ospf ) protocol="89" ;;
			pim ) protocol="103" ;;
			* ) protocol=`echo ${proto} | egrep '[0-9]{1,3}'` ;;
		esac
	fi
	echo "${port_num}/${protocol}"
}



function list_filter(){
	local file_input=${1}
	local file_output=${2}
	local protocol
	local filter=filter
	local interface
	local filter_num
	local access_list_num
	local temp=`mktemp`
	local line_mod
	local line_rtx
	local line_rtx_mod
	echo -n > ${file_output}
	cat ${file_input} | sort | grep filter > ${temp}
	cat ${temp} | egrep 'secure filter' | egrep 'lan|pp' | sed -e "s|^ ip|ip|g" | \
	while read line; do
		protocol=`echo ${line} | awk '{print $1}'`
		interface=`echo ${line} | awk '{print $2}'`
		dir=`echo ${line} | awk '{print $5}'`
		line_mod=`echo ${line} | awk '{for(i=6;i<NF;i++){printf("%s%s",$i,OFS=" ")}print $NF}'`
		static=`echo ${line_mod} | awk -F'dynamic ' '{print $1}' | sed -e "s| $||g" -e "s|\ |\||g"`
		dynamic=`echo ${line_mod} | awk -F'dynamic ' '{print $2}' | sed -e "s| $||g" -e "s|\ |\||g"`
		cat ${temp} | egrep "${protocol} ${filter} [0-9]" | egrep "${static}" | \
		while read line; do
			echo "${interface} ${dir} ${line}" >> ${file_output}
		done

		if [ "${dynamic}" != "" ]; then
			cat ${temp} | egrep "${protocol} ${filter} dynamic [0-9]" | egrep "${dynamic}" | \
			while read line; do
				echo "${dir} ${line}" >> ${file_output}
			done
		fi
	done
	rm ${temp}
}

function main(){
	local input_file=${1}
	local input_file_temp=`mktemp`
	local config=("")
	local config_label=("")
	local port_range=("" "")
	echo -n > "${input_file}.ios"
	list_filter "${input_file}" "${input_file_temp}"
	
	cat ${input_file_temp} | \
	egrep -v 'ipv*6* filter dynamic' | \
	while read line; do
		check=`echo "${line}" | egrep '^\!ip'`
		line_org="${line}"
		line=`echo "${line}" | sed -e 's|filter|access-list|g' -e 's|reject|deny|g' -e 's|pass|permit|g' -e "s|\*|any|g"`
		unset config[@]
		unset config_label[@]
		port_range=("false" "false")
		for data in `echo "${line}"`; do
			config=("${config[@]}" "${data}")
		done


		config_label=( 'interface' 'direction' 'ip-or-ipv6' 'filter_cmd' 'filter_id' )
		count_interface=0
		count_direction=1
		count_address_family=2
		count_command=3
		count_filter_num=4
		
		count=${#config_label[@]}
		count_action=${count}
		config_label=("${config_label[@]}" "filter_act")

		count=`expr ${count} + 1`
		count_src_addr=${count}
		config[${count}]=`wildcard ${config[${count_address_family}]} ${config[${count}]}`
		config_label=("${config_label[@]}" "src_addr")

		count=`expr ${count} + 1`
		count_dst_addr=${count}
		config[${count}]=`wildcard ${config[${count_address_family}]} ${config[${count}]}`
		config_label=("${config_label[@]}" "dst_addr")

		count=`expr ${count} + 1`
		count_protocol=${count}
		if [ "${config[${count}]}" != "any" ]; then
			config[${count}]="`echo "${config[${count}]}" | sed -e "s|\,|\n|g" | sort | sed -r -e ':loop;N;$!b loop;s/\n/ /g'`"
		else
			config[${count}]=${config[${count_address_family}]}
		fi
		config_label=("${config_label[@]}" "protocol")

		count=`expr ${count} + 1`
		count_src_port=${count}
		count_plus=`expr ${count} + 1`
		count_dst_port=${count_plus}
		for num in ${count} ${count_plus}; do
			if [ "${config[${num}]}" != "any" ]; then
				if [ "${config[${num}]}" == "" ]; then
					config[${count}]="any"
				fi
				check=`echo "${config[${num}]}" | sed "s|\-| |g"`
				if [ "${check}" != "${config[${num}]}" ]; then
					port_range[`expr ${num} - ${count}`]="true"
					config[${num}]="${check}"
				else
					config[${num}]=`echo "${config[${num}]}" | sed -e "s|\,| |g"`
				fi
				for j in ${config[${count_protocol}]}; do
					for k in ${config[${num}]}; do
						m=`niemonic_rtx "${j}" "${k}" | awk -F'/' '{print $1}'`
						if [ "${m}" != "" ]; then
							l="${l} ${m}"
						fi
						l=`echo "${l}" | sed "s| |\n|g" | sort -n | uniq | sed -r -e ':loop;N;$!b loop;s/\n/ /g' | sed "s|^ ||g"`
					done
				done
				config[${num}]="${l}"
				l=""
			fi
		done
		config_label=("${config_label[@]}" "src_port" "dst_port")
		count=${num}

###POST-PROCESS

		if [ "${seq_check}" != "${config[${count_address_family}]}-${config[${count_direction}]}" ]; then
			seq_num=0
		fi
		seq_check="${config[${count_address_family}]}-${config[${count_direction}]}"
		seq_num=`expr ${seq_num} + 1`

		if [ "${config[${count_protocol}]}" == "${config[${count_address_family}]}" ]; then
			config[${count_src_port}]="-"
			config[${count_dst_port}]="-"
		else
			for j in ${config[${count_protocol}]}; do
				m=`niemonic_rtx "${j}" "0" | awk -F'/' '{print $2}'`
				if [ "${m}" != "" ]; then
					l="${l} ${m}"
				fi
				l=`echo "${l}" | sed "s| |\n|g" | sort -n | uniq | sed -r -e ':loop;N;$!b loop;s/\n/ /g' | sed "s|^ ||g"`
			done
			config[${count_protocol}]="${l}"
			l=""
		fi

		if "${port_range[`expr ${count_src_port} - ${count_src_port}`]}"; then
			config[${count_src_port}]=`echo "range_${config[${count_src_port}]}" | sed -e 's| |_|g'`
		else
			if [ "${config[${count_src_port}]}" != "any" ] && [ "${config[${count_src_port}]}" != "-" ]; then
				for var in `echo "${config[${count_src_port}]}" | sed "s| |\n|g" | sort -n -r | sed -r -e ':loop;N;$!b loop;s/\n/ /g' | sed "s|^ ||g"`; do
					l="eq_${var} ${l}"
				done
				config[${count_src_port}]=`echo "${l}" | sed -e "s|\ $||g"`
				l=""
			fi
		fi

		if "${port_range[`expr ${count_dst_port} - ${count_src_port}`]}"; then
			config[${count_dst_port}]=`echo "range_${config[${count_dst_port}]}" | sed -e 's| |_|g'`
		else
			if [ "${config[${count_dst_port}]}" != "any" ] && [ "${config[${count_dst_port}]}" != "-" ]; then
				for var in `echo "${config[${count_dst_port}]}" | sed "s| |\n|g" | sort -n -r | sed -r -e ':loop;N;$!b loop;s/\n/ /g' | sed "s|^ ||g"`; do
					l="eq_${var} ${l}"
				done
				config[${count_dst_port}]=`echo "${l}" | sed -e "s|\ $||g"`
				l=""
			fi
		fi


		check=`echo "${config[${count_action}]}" | awk -F'-' '{print $2}'`
		if [ "${check}" != "" ]; then
			count=`expr ${count} + 1`
			count_action_log=${count}
			config[${count_action}]=`echo "${config[${count_action}]}" | awk -F'-' '{print $1}'`
			config=("${config[@]}" "${str}")
			config_label=("${config_label[@]}" "log_activity")
		fi

		check=`echo ${config[${count_direction}]} | awk -F',' '{print $1}'`
		if [ "${check}" == "in" ]; then
			if [ "${config[${count_address_family}]}" == "ipv6" ]; then
				config[${count_filter_num}]=INv6
			fi
			if [ "${config[${count_address_family}]}" == "ip" ]; then
				config[${count_filter_num}]=101
			fi
		fi
		if [ "${check}" == "out" ]; then
			if [ "${config[${count_address_family}]}" == "ipv6" ]; then
				config[${count_filter_num}]=OUTv6
			fi
			if [ "${config[${count_address_family}]}" == "ip" ]; then
				config[${count_filter_num}]=100
			fi
		fi

		echo "${line_org}" | awk '{for(i=3;i<NF;i++){printf("%s%s",$i,OFS=" ")}print $NF}' | sed "s|^|\!|g"

	    if [ "${config[${count_protocol}]}" != "${config[${count_address_family}]}" ]; then
			for fproto in ${config[${count_protocol}]}; do
				if [ "${fproto}" == "tcp" ] || [ "${fproto}" == "udp" ]; then
					if [ "${config[${count_dst_port}]}" != "any" ]; then
						echo -e "! ------------------------------------"
						for num in `seq 0 ${count_dst_addr}`; do
							if [ "${config[${num}]}" != "-" ]; then
						    	echo -e "! ${config_label[${num}]} : ${config[${num}]}"
						    fi
						done
						for fsport in ${config[${count_src_port}]}; do
							for fdport in ${config[${count_dst_port}]}; do
								echo -e "! ------------------------------------"
								echo -e "! ${config_label[${count_protocol}]} : ${fproto}"
								fdport=`echo "${fdport}" | sed 's|_| |g'`
								fsport=`echo "${fsport}" | sed 's|_| |g'`
								echo -e "! ${config_label[${count_src_port}]} : ${fsport}"
								echo -e "! ${config_label[${count_dst_port}]} : ${fdport}"
								if [ "${config[${count_address_family}]}" == "ipv6" ]; then
									echo "${config[${count_address_family}]} ${config[${count_command}]} ${config[${count_filter_num}]}" | tee -a ${config_file}.ios
									echo " sequence ${seq_num} ${config[${count_action}]} ${fproto} ${config[${count_src_addr}]} ${config[${count_dst_addr}]} ${fdport}" | tee -a ${config_file}.ios
								else
									echo "${config[${count_command}]} ${config[${count_filter_num}]} ${config[${count_action}]} ${fproto} ${config[${count_src_addr}]} ${config[${count_dst_addr}]} ${fdport}" | tee -a ${config_file}.ios
								fi
								seq_num=`expr ${seq_num} + 1`
							done
						done
					else
						echo "! ------ entry ignored: protocol is ${fproto} and destination port is ${config[${count_dst_port}]} ------"
					fi
				else
					echo -e "! ------------------------------------"
					for num in `seq 0 ${count_dst_addr}`; do
						if [ "${config[${num}]}" != "-" ]; then
					    	echo -e "! ${config_label[${num}]} : ${config[${num}]}"
					    fi
					done
					if [ "${config[${count_address_family}]}" == "ipv6" ]; then
						echo "${config[${count_address_family}]} ${config[${count_command}]} ${config[${count_filter_num}]}" | tee -a ${config_file}.ios
						echo " sequence ${seq_num} ${config[${count_action}]} ${config[${count_protocol}]} ${config[${count_src_addr}]} ${config[${count_dst_addr}]}" | tee -a ${config_file}.ios
					else
						echo "${config[${count_command}]} ${config[${count_filter_num}]} ${config[${count_action}]} ${config[${count_protocol}]} ${config[${count_src_addr}]} ${config[${count_dst_addr}]}" | tee -a ${config_file}.ios
					fi
				fi
			done
		else
			echo -e "! ------------------------------------"
			for num in `seq 0 ${count_dst_addr}`; do
				if [ "${config[${num}]}" != "-" ]; then
			    	echo -e "! ${config_label[${num}]} : ${config[${num}]}"
			    fi
			done
			if [ "${config[${count_address_family}]}" == "ipv6" ]; then
				echo "${config[${count_address_family}]} ${config[${count_command}]} ${config[${count_filter_num}]}" | tee -a ${config_file}.ios
				echo " sequence ${seq_num} ${config[${count_action}]} ${config[${count_protocol}]} ${config[${count_src_addr}]} ${config[${count_dst_addr}]}" | tee -a ${config_file}.ios
			else
				echo "${config[${count_command}]} ${config[${count_filter_num}]} ${config[${count_action}]} ${config[${count_protocol}]} ${config[${count_src_addr}]} ${config[${count_dst_addr}]}" | tee -a ${config_file}.ios
			fi
		fi
		echo -e "! ------------------------------------------------------------------------"
	done
	rm ${input_file_temp}
}


if [ "${1}" != "" ]; then
	config_file=${1}
else
	config_file=sample.cfg
fi

#cat ${config_file}.bak.v4 | sed -r -e ':loop;N;$!b loop;s/\n/\t/g' -e "s|\t\#|\n\#|g" -e "s|pp select|\npp select|g" -e "s|tunnel select|\ntunnel select|g" -e "s|ip lan|\nip lan|g" -e "s|ipv6 lan|\nipv6 lan|g" | \
#egrep 'ip|pp' | sed -r -e ':loop;N;$!b loop;s/\t/\n/g' -e "s|\t\#|\n\#|g" | egrep -v 'ipv6|tunnel|route|ppp|null|loopback|auth|nat|mtu|snmp |^dns|^analog|^ngn|^vlan|^\#|description pp|netvolante|address|keepalive|intrusion|always|directed-broadcast|enable|prefix|rtadv|service|mld|disable|^sip' > ${config_file}

#cat ${config_file}.bak.v6 | sed -r -e ':loop;N;$!b loop;s/\n/\t/g' -e "s|\t\#|\n\#|g" -e "s|pp select|\npp select|g" -e "s|tunnel select|\ntunnel select|g" -e "s|ip lan|\nip lan|g" -e "s|ipv6 lan|\nipv6 lan|g" | \
#egrep 'ipv6|lan' | sed -r -e ':loop;N;$!b loop;s/\t/\n/g' -e "s|\t\#|\n\#|g" | egrep -v 'ip |tunnel|route|ppp|null|loopback|auth|nat|mtu|snmp |^dns|^analog|^ngn|^vlan|^\#|description pp|netvolante|address|keepalive|intrusion|always|directed-broadcast|enable|prefix|rtadv|service|mld|disable|^sip' >> ${config_file}

main ${config_file}

