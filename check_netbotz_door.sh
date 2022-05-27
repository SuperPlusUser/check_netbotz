#!/bin/bash
#
# requires NET-SNMP 5.x
# Put here /usr/lib/nagios/plugins/
#
PLUGIN_NAME="Icinga plugin check command for door sensor monitoring on Netbotz 250, 3xx and 4xx RackMonitor Devices with PowerNet-MIB or NETBOTZ-MIB"
PLUGIN_VERSION="2022.05.1"
PRINTINFO=`printf "\n%s, version %s\n \n" "$PLUGIN_NAME" "$PLUGIN_VERSION"`
#
# Exit codes
#
codeOK=0
codeWARNING=1
codeCRITICAL=2
codeUNKNOWN=3
#
# Default Values
#
MIB="autodetect"
#
# Value Mappings
#
status_codes=("normal" "info" "warning" "error" "critical" "failure")
value_codes=("N/A" "open" "closed")
#
# OIDs
#
# Powernet-MIB:
emsDoorSensorName=".1.3.6.1.4.1.318.1.1.10.3.20.8.1.2"        # String
emsDoorSensorLocation=".1.3.6.1.4.1.318.1.1.10.3.20.8.1.3"    # String
emsDoorSensorValue=".1.3.6.1.4.1.318.1.1.10.3.20.8.1.4"       # INT: 1:open, 2:closed
emsDoorSensorCommStatus=".1.3.6.1.4.1.318.1.1.10.3.20.8.1.6"  # INT: 1:commOK

# Netbotz-MIB:
DoorSwitchName="1.3.6.1.4.1.5528.100.4.2.2.1.4"     # String
DoorSwitchStatus="1.3.6.1.4.1.5528.100.4.2.2.1.3"   # INT: severity level of error status -> status_codes
DoorSwitchValue="1.3.6.1.4.1.5528.100.4.2.2.1.2"    # INT: -1: N/A, 0:open, 1:closed -> value_codes -1

DryContactName="1.3.6.1.4.1.5528.100.4.2.1.1.4"     # String
DryContactStatus="1.3.6.1.4.1.5528.100.4.2.1.1.3"   # INT: severity level of error status -> status_codes
DryContactValue="1.3.6.1.4.1.5528.100.4.2.1.1.2"    # INT: -1: N/A, 0:open, 1:closed -> value_codes -1



# ---------- Script options help ----------
#
Usage() {
  echo "$PRINTINFO"
  echo "Usage: $0 [OPTIONS]

Option   GNU long option     Meaning
------   ---------------     -------
 -H      --hostaddr          Host address (Icinga object host.address)
 -P      --protocol          SNMP protocol version. Possible values: 2c|3
 -C      --community         SNMPv2c community string for SNMP communication (for example 'public')
 -a      --authproto         SNMPv3 auth proto. Possible values: MD5|SHA
 -x      --privproto         SNMPv3 priv proto. Possible values: DES|AES
 -U      --secname           SNMPv3 username
 -A      --authpassword      SNMPv3 authentication password
 -X      --privpasswd        SNMPv3 privacy password
 -m      --mib               MIB to use. Possible values: powernet (e.g. used by NetBotz 250) or netbotz (e.g. used by NetBotz 320E and 450)
 -q      --help              Show this message
 -v      --version           Print version information and exit

Usage examples.
For SNMPv2:
$0 -H 10.10.10.10 -P 2c -C public -m powernet
For SNMPv3:
$0 -H 10.10.10.10 -P 3 -U icinga -a MD5 -A myAuthPzwD -x DES -X myPrivPw0d -m netbotz

"
}


# ---------- Parse script arguments ----------
#
if [ -z $1 ]; then
    Usage; exit $codeUNKNOWN;
fi
#
OPTS=`getopt -o H:P:C:a:x:U:A:X:m:qv -l hostname:,hostaddr:,protocol:,community:,authproto:,privproto:,secname:,authpassword:,privpasswd:,mib:,help,version -- "$@"`
eval set -- "$OPTS"
while true; do
   case $1 in
     -H|--hostaddr) HOST=$2 ; shift 2 ;;
     -P|--protocol)
        case "$2" in
        "2c"|"3") PROTOCOL=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use '2c' or '3'\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -C|--community)     COMMUNITY=$2 ; shift 2 ;;
#     -L|--seclevel)
#        case "$2" in
#        "noAuthNoPriv"|"authNoPriv"|"authPriv") v3SECLEVEL=$2 ; shift 2 ;;
#        *) printf "Unknown value for option %s. Use 'noAuthNoPriv' or 'authNoPriv' or 'authPriv'\n" "$1" ; exit $codeUNKNOWN ;;
#        esac ;;
     -a|--authproto)
        case "$2" in
        "MD5"|"SHA") v3AUTHPROTO=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use 'MD5' or 'SHA'\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -x|--privproto)
        case "$2" in
        "DES"|"AES") v3PRIVPROTO=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use 'DES' or 'AES'\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -U|--secname)       v3SECNAME=$2 ; shift 2 ;;
     -A|--authpassword)  v3AUTHPWD=$2 ; shift 2 ;;
     -X|--privpasswd)    v3PRIVPWD=$2 ; shift 2 ;;
     -m|--mib)
        case "$2" in
        "powernet"|"netbotz") MIB=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use 'powernet' for NetBotz 250 or 'netbotz' for NetBotz 3xx or 4xx. Leave out for auto detection.\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -q|--help)          Usage ; exit $codeOK ;;
     -v|--version)       echo "$PRINTINFO" ; exit $codeOK ;;
     --) shift ; break ;;
     *)  Usage ; exit $codeUNKNOWN ;;
   esac
done


# ---------- Set SNMP connection paramaters ----------
#
vCS=$( echo " -O qvn -v $PROTOCOL" )

if [ "$PROTOCOL" = "1" ] || [ "$PROTOCOL" = "2c" ]
then
   vCS=$vCS$( echo " -c $COMMUNITY" );
elif [ "$PROTOCOL" = "3" ] && [ -n "$v3AUTHPROTO" ] && [ -n "$v3PRIVPROTO" ]
then
   vCS=$vCS$( echo " -l authPriv" );
   vCS=$vCS$( echo " -a $v3AUTHPROTO" );
   vCS=$vCS$( echo " -x $v3PRIVPROTO" );
   vCS=$vCS$( echo " -A $v3AUTHPWD" );
   vCS=$vCS$( echo " -X $v3PRIVPWD" );
   vCS=$vCS$( echo " -u $v3SECNAME" );
elif [ "$PROTOCOL" = "3" ] && [ -n "$v3AUTHPROTO" ]
then
   vCS=$vCS$( echo " -l authNoPriv" );
   vCS=$vCS$( echo " -a $v3AUTHPROTO" );
   vCS=$vCS$( echo " -A $v3AUTHPWD" );
   vCS=$vCS$( echo " -u $v3SECNAME" );
elif [ "$PROTOCOL" = "3" ]
then
   vCS=$vCS$( echo " -l noAuthNoPriv" );
   vCS=$vCS$( echo " -u $v3SECNAME" );
else
   Usage
   exit $codeUNKNOWN
fi

vCS=$vCS$( echo " $HOST" );


# ---------- Get SNMP-data functions ----------

GetData()
{ # Parameter:    $1 = OID
  #               $2 = Variable to save snmpget results

  declare -n fRes=$2
  fRes=$( snmpget $vCS $1 2>&1 )
  rcode=$?

  if [ "$rcode" -ne "0" ]; then
    echo "Plugin error: $(echo $fRes |  cut -c1-100)"
    # Wrong credentials or host not reachable? -> exit directly
    exit $codeUNKNOWN
  fi

  if echo "$fRes" | grep -q "^No Such .* at this OID$"
  then
    #echo "Plugin error: $fRes - $1"
    snmp_error="$fRes - $1"
    return $codeUNKNOWN
  fi

  return $codeOK
}

GetBulkData()
{ # Parameter:    $1 = OID,
  #               $2 = Array to save snmpbulkwalk results

  declare -n aRes=$2
  fRes=$( snmpbulkwalk $vCS $1 2>&1 )
  rcode=$?

  if [ "$rcode" -ne "0" ]; then
    echo "Plugin error: $(echo ${fRes} |  cut -c1-100)"
    # Wrong credentials or host not reachable? -> exit directly
    exit $codeUNKNOWN
  fi

  if echo "$fRes" | grep -q "^No Such .* at this OID$"
  then
    #echo "Plugin error: $fRes - $1"
    snmp_error="$fRes - $1"
    return $codeUNKNOWN
  fi

  # create an array of bulkwalk results
  mapfile -t aRes < <( echo "$fRes" )

  return $codeOK
}

# ---------- Get all the SNMP-Values we need ----------
if [ $MIB == "powernet" ] || [ $MIB == "autodetect" ]
  then
    GetBulkData $emsDoorSensorName aSenName
    if [ $? -eq "0" ]
      then
        MIB="powernet"

        GetBulkData $emsDoorSensorLocation aSenLoc
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        GetBulkData $emsDoorSensorValue aSenValue
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        GetBulkData $emsDoorSensorCommStatus aSenCommStatus
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
    fi
fi

if [ $MIB == "netbotz" ] || [ $MIB == "autodetect" ]
  then
    GetBulkData $DoorSwitchName aDoorSwitchName
    if [ $? -eq "0" ]
      then
        MIB="netbotz"

        GetBulkData $DoorSwitchStatus aDoorSwitchStatus
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        GetBulkData $DoorSwitchValue aDoorSwitchValue
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
    fi

    GetBulkData $DryContactName aDryContactName
    if [ $? -eq "0" ]
      then
        MIB="netbotz"

        GetBulkData $DryContactStatus aDryContactStatus
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        GetBulkData $DryContactValue aDryContactValue
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
    fi
fi

total_sensors=$((${#aSenName[@]} + ${#aDoorSwitchName[@]} + ${#aDryContactName[@]}))

if [ $total_sensors -eq 0 ]
  then
    echo "Plugin error: No door sensors detected!"
    echo "MIB: $MIB"
    echo "Last SNMP Error: $snmp_error"
    exit $codeUNKNOWN
fi


# ---------- Create plugin output ----------
summary=""
details=""
perfdata=""

crit=0
warn=0

GenerateOutput()
{
  value_str="${value_codes[$value]}"
  status_str="${status_codes[$status]}"
  label="$( echo $name | sed 's/"//g;s/[ '\''=.|$#&/()%*@]/_/g' )" # remove " and replace space and some special characters with _

  if [ $con_status -eq 1 ]
    then
      perfdata+="'${label}'=${value};;2:;0;2 "
      if [ "$status" -lt "2" ]
        then
            #summary+="${sen_type} ${name} is ${value_str}. "
            details+="\n[OK] "
        elif [ "$status" -eq "2" ]
          then
            (( warn++ ))
            summary+="${sen_type} ${name} is ${value_str}! "
            details+="\n[WARNING] "
        else
            (( crit++ ))
            summary+="${sen_type} ${name} is ${value_str}! "
            details+="\n[CRITICAL] "
      fi
      details+="${sen_type} ${name}${location} is ${value_str}."
      if [ "$MIB" == "netbotz" ]
        then
          details+=" Netbotz status code ${status} (${status_str})."
      fi
  else
      (( warn++ ))
      perfdata+="'$label'=0;;2:;0;2 " # disconnected sensor gets value 0
      summary+="${sen_type} sensor ${name} disconnected! "
      details+="\n[WARNING] ${sen_type} sensor ${name}${location} disconnected! Reconnect sensor or reboot netbotz to delete the sensor!"
  fi

}

for ((i=0; i<"${#aSenName[@]}"; i++)); do
  sen_type="Door"
  name="${aSenName[$i]}"
  value=${aSenValue[$i]}
  if [ "$value" -eq "2" ]; then status=0; else status=4; fi # Powernet-MIB does not have error status codes for door sensors.
  location=" at ${aSenLoc[$i]}"
  con_status=${aSenCommStatus[$i]}
  GenerateOutput
done

for ((i=0; i<"${#aDoorSwitchName[@]}"; i++)); do
  sen_type="Door switch"
  name="${aDoorSwitchName[$i]}"
  value=$(( ${aDoorSwitchValue[$i]} + 1 ))
  status=${aDoorSwitchStatus[$i]}
  location=""
  con_status=1 # always report as connected -> disconnected message only working for Netbotz 250 at the moment
  GenerateOutput
done

for ((i=0; i<"${#aDryContactName[@]}"; i++)); do
  sen_type="Dry contact"
  name="${aDryContactName[$i]}"
  value=$(( ${aDryContactValue[$i]} + 1 ))
  status=${aDryContactStatus[$i]}
  location=""
  con_status=1 # always report as connected -> disconnected message only working for Netbotz 250 at the moment
  GenerateOutput
done

if [ $total_sensors -eq 1 ]
  then
    summary="1 door sensor detected. $summary"
  else
    summary="$total_sensors door sensors detected. $summary"
fi

if [ "$crit" -gt 0 ]
  then
    summary="SNMP CRITICAL - $summary"
    exitCode=$codeCRITICAL
  elif [ "$warn" -gt 0 ]
    then
      summary="SNMP WARNING - $summary"
      exitCode=$codeWARNING
  else
    summary="SNMP OK - ${summary}All doors are closed."
    exitCode=$codeOK
fi

printf "%s%b | %s\n" "$summary" "$details" "$perfdata"

exit $exitCode
