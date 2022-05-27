#!/bin/bash
#
# requires NET-SNMP 5.x
# Put here /usr/lib/nagios/plugins/
#
PLUGIN_NAME="Icinga plugin check command for temperature and humidity sensor monitoring on Netbotz 250, 3xx and 4xx RackMonitor devices with PowerNet-MIB or NETBOTZ-MIB"
PLUGIN_VERSION="v1.0"
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
TYPE="temp"
#
# Value Mappings
#
error_status_codes=("normal" "info" "warning" "error" "critical" "failure")
comm_status_codes=("N/A" "communication never established" "normal" "communication lost" )
#
# OIDs
#
# Powernet-MIB:
oEmsName="1.3.6.1.4.1.318.1.1.10.3.13.1.1.2"         # String
oEmsCommStatus="1.3.6.1.4.1.318.1.1.10.3.13.1.1.10"  # INT: 1: comm. never established, 2: normal, 3: comm. lost
oEmsAlarmStatus="1.3.6.1.4.1.318.1.1.10.3.13.1.1.11" # INT: The alarm status of the probe.
# This integer should be interpreted as a bit map, with each bit representing the presence or absence of the specific alarm conditions listed below.
# The bit will be '1' if the condition is present, and '0' if the condition is not present.
# Bit Hex. Value  Description
# 1   0x0001      Maximum temperature exceeded.
# 2   0x0002      High temperature exceeded.
# 3   0x0004      Low temperature exceeded.
# 4   0x0008      Minimum temperature exceeded.
# 5   0x0010      Short-term increasing temperature rate exceeded.
# 6   0x0020      Short-term decreasing temperature rate exceeded.
# 7   0x0040      Long-term increasing temperature rate exceeded.
# 8   0x0080      Long-term decreasing temperature rate exceeded.
# 9   0x0100      Maximum humidity exceeded.
# 10  0x0200      High humidity exceeded.
# 11  0x0400      Low humidity exceeded.
# 12  0x0800      Minimum humidity exceeded.

oEmsTempValue="1.3.6.1.4.1.318.1.1.10.3.13.1.1.3"
oEmsTempHigh="1.3.6.1.4.1.318.1.1.10.3.13.1.1.4"
oEmsTempLow="1.3.6.1.4.1.318.1.1.10.3.13.1.1.5"
oEmsTempMax="1.3.6.1.4.1.318.1.1.10.3.13.1.1.12"
oEmsTempMin="1.3.6.1.4.1.318.1.1.10.3.13.1.1.13"

oEmsHumValue="1.3.6.1.4.1.318.1.1.10.3.13.1.1.6"
oEmsHumHigh="1.3.6.1.4.1.318.1.1.10.3.13.1.1.7"
oEmsHumLow="1.3.6.1.4.1.318.1.1.10.3.13.1.1.8"
oEmsHumMax="1.3.6.1.4.1.318.1.1.10.3.13.1.1.14"
oEmsHumMin="1.3.6.1.4.1.318.1.1.10.3.13.1.1.15"

# Netbotz-MIB:
oNbTempName="1.3.6.1.4.1.5528.100.4.1.1.1.4"        # String
oNbTempErrorStatus="1.3.6.1.4.1.5528.100.4.1.1.1.3" # Errorstatus -> status_codes
oNbTempValue="1.3.6.1.4.1.5528.100.4.1.1.1.8"       # INT: Deg. C

oNbHumName="1.3.6.1.4.1.5528.100.4.1.2.1.4"         # String
oNbHumErrorStatus="1.3.6.1.4.1.5528.100.4.1.2.1.3"  # Errorstatus -> status_codes
oNbHumValue="1.3.6.1.4.1.5528.100.4.1.2.1.8"        # INT: Hum %


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
 -A      --authpasswd        SNMPv3 authentication password
 -X      --privpasswd        SNMPv3 privacy password
 -m      --mib               MIB to use. Possible values: 'powernet' (e.g. used by NetBotz 250) or 'netbotz' (e.g. used by NetBotz 320E and 450)
 -t      --type              Test Type. Valid values are 'temp' for temperature test, and 'humid' for humidity tests. [Default:temp]
 -w      --warn-low          Set warning low threshold. For Devices with powernet mib, the threshold will be retrieved from the device if this option is omitted.
 -W      --warn-high         Set warning high threshold. For Devices with powernet mib, the threshold will be retrieved from the device if this option is omitted.
 -z      --crit-low          Set critical low threshold. For Devices with powernet mib, the threshold will be retrieved from the device if this option is omitted.
 -Z      --crit-high         Set critical high threshold. For Devices with powernet mib, the threshold will be retrieved from the device if this option is omitted.
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
OPTS=`getopt -o H:P:C:a:x:U:A:X:m:t:w:W:z:Z:qv -l hostname:,hostaddr:,protocol:,community:,authproto:,privproto:,secname:,authpasswd:,privpasswd:,mib:,type:,warn-low:,warn-high:,crit-low:,crit-high:,help,version -- "$@"`
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
     -A|--authpasswd)    v3AUTHPWD=$2 ; shift 2 ;;
     -X|--privpasswd)    v3PRIVPWD=$2 ; shift 2 ;;
     -m|--mib)
        case "$2" in
        "powernet"|"netbotz") MIB=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use 'powernet' for NetBotz 250 or 'netbotz' for NetBotz 3xx or 4xx. Leave out for auto detection.\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -t|--type)
        case "$2" in
        "temp"|"humid") TYPE=$2 ; shift 2 ;;
        *) printf "Unknown value for option %s. Use 'temp' for temperature test or 'humid' for humidity test.\n" "$1" ; exit $codeUNKNOWN ;;
        esac ;;
     -w|--warn-low)      WLOW=$2  ; shift 2 ;;
     -W|--warn-high)     WHIGH=$2 ; shift 2 ;;
     -z|--crit-low)      CLOW=$2  ; shift 2 ;;
     -Z|--crit-high)     CHIGH=$2 ; shift 2 ;;
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
    GetBulkData $oEmsName aSenName
    if [ $? -eq "0" ]
      then
        MIB="powernet"

        GetBulkData $oEmsCommStatus aSenCommStatus
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        GetBulkData $oEmsAlarmStatus aSenAlarmStatus
         if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        if [ $TYPE == "temp" ]
          then
            GetBulkData $oEmsTempValue aSenValue
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

            if [ -z "$WLOW" ]
              then
                GetBulkData $oEmsTempLow aSenLow
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$WHIGH" ]
              then
                GetBulkData $oEmsTempHigh aSenHigh
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$CLOW" ]
              then
                GetBulkData $oEmsTempMin aSenMin
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$CHIGH" ]
              then
                GetBulkData $oEmsTempMax aSenMax
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

        elif [ $TYPE == "humid" ]
          then
            GetBulkData $oEmsHumValue aSenValue
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

            if [ -z "$WLOW" ]
              then
                GetBulkData $oEmsHumLow aSenLow
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$WHIGH" ]
              then
                GetBulkData $oEmsHumHigh aSenHigh
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$CLOW" ]
              then
                GetBulkData $oEmsHumMin aSenMin
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi

            if [ -z "$CHIGH" ]
              then
                GetBulkData $oEmsHumMax aSenMax
                 if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
            fi
        fi
    fi
fi

if [ $MIB == "netbotz" ] || [ $MIB == "autodetect" ]
  then
    if [ $TYPE == "temp" ]
      then
        GetBulkData $oNbTempName aSenName
        if [ $? -eq "0" ]
          then
            MIB="netbotz"

            GetBulkData $oNbTempValue aSenValue
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

            GetBulkData $oNbTempErrorStatus aSenErrorStatus
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi
        fi


    elif [ $TYPE == "humid" ]
      then
        GetBulkData $oNbHumName aSenName
        if [ $? -eq "0" ]
          then
            MIB="netbotz"

            GetBulkData $oNbHumValue aSenValue
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

            GetBulkData $oNbHumErrorStatus aSenErrorStatus
             if [ $? -ne "0" ]; then echo $snmp_error; exit $codeUNKNOWN; fi

        fi

    fi

fi

total_sensors="${#aSenName[@]}"

if [ $total_sensors -eq 0 ]
  then
    echo "Plugin error: No sensors detected!"
    echo "MIB: $MIB"
    echo "Last SNMP error: $snmp_error"
    exit $codeUNKNOWN
fi


# ---------- Generate plugin output ----------
summary=""
details=""
perfdata=""

crit=0
warn=0

if [ $TYPE == "temp" ]
then
  measurement="Temperature"
  unit="°C"
  unit_perf="C"
else
  measurement="Humidity"
  unit="% RH"
  unit_perf="%"
fi

for ((i=0; i<"${#aSenName[@]}"; i++)); do
  name="${aSenName[$i]}"
  label="$( echo $name | sed 's/"//g;s/[ '\''=.|$#&/()%*@]/_/g' )" # remove " and replace space and some special characters with _
  value="${aSenValue[$i]}"
  sen_err=""

  if [ -n "$WLOW" ]
    then
      wLowThreshold="$WLOW"
    else
      wLowThreshold="${aSenLow[$i]}"
  fi

  if [ -n "$WHIGH" ]
    then
      wHighThreshold="$WHIGH"
    else
      wHighThreshold="${aSenHigh[$i]}"
  fi

  if [ -n "$CLOW" ]
    then
      cLowThreshold="$CLOW"
    else
      cLowThreshold="${aSenMin[$i]}"
  fi

  if [ -n "$CHIGH" ]
    then
      cHighThreshold="$CHIGH"
    else
      cHighThreshold="${aSenMax[$i]}"
  fi

  if [ -n "${aSenCommStatus[$i]}" ]
    then
      con_status="${aSenCommStatus[$i]}"
    else
      con_status=2 # Netbotz mib has no connection status -> always consider sensor as connected normal (2)
  fi

  if [ -n "${aSenAlarmStatus[$i]}" ]
    then
      alarm_status="${aSenAlarmStatus[$i]}"
    else
      alarm_status=0 # Netbotz mib has no alarm status -> always consider as normal (0)
  fi

  if [ -n "${aSenErrorStatus[$i]}" ]
    then
      error_status="${aSenErrorStatus[$i]}"
    else
      error_status=0 # Powernet mib has no error status -> always consider sensor as normal (0)
  fi

  if [ $con_status -eq 2 ]
    then
      perfdata+="'${label}'=${value}${unit_perf};${wLowThreshold}:${wHighThreshold};${cLowThreshold}:${cHighThreshold};; "

      # check netbotz-mib error status
      if [ "$error_status" -ge 2 ]
        then
          sen_err+="- Netbotz status code ${error_status} (${error_status_codes[$error_status]}). "
      fi

      # Now check powernet-mib alarm status
      if [ $TYPE == "temp" ] && [ $MIB == "powernet" ]
        then
          # Bit Hex. Value  Description
          # 1   0x0001      Maximum temperature exceeded.
          # 2   0x0002      High temperature exceeded.
          # 3   0x0004      Low temperature exceeded.
          # 4   0x0008      Minimum temperature exceeded.
          # 5   0x0010      Short-term increasing temperature rate exceeded.
          # 6   0x0020      Short-term decreasing temperature rate exceeded.
          # 7   0x0040      Long-term increasing temperature rate exceeded.
          # 8   0x0080      Long-term decreasing temperature rate exceeded.

          if [ $(( $alarm_status & ( 1 << 0 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Maximum temperature exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 1 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: High temperature exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 2 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Low temperature exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 3 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Minimum temperature exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 4 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Short-term increasing temperature rate exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 5 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Short-term decreasing temperature rate exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 6 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Long-term increasing temperature rate exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 7 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Long-term decreasing temperature rate exceeded. "
          fi

      fi

      if [ $TYPE == "humid" ] && [ $MIB == "powernet" ]
        then
          # 9   0x0100      Maximum humidity exceeded.
          # 10  0x0200      High humidity exceeded.
          # 11  0x0400      Low humidity exceeded.
          # 12  0x0800      Minimum humidity exceeded.

          if [ $(( $alarm_status & ( 1 << 8 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Maximum humidity exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 9 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: High humidity exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 10 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Low humidity exceeded. "
          fi

          if [ $(( $alarm_status & ( 1 << 11 ) )) -ne 0 ]
            then
              sen_err+="- Netbotz alarm: Minimum humidity exceeded. "
          fi

      fi

      # if we do not have thresholds, now set some which always match:
      if [ -z "$wLowThreshold" ];  then wLowThreshold="-999"; fi
      if [ -z "$wHighThreshold" ]; then wHighThreshold="999"; fi
      if [ -z "$cLowThreshold" ];  then cLowThreshold="-999"; fi
      if [ -z "$cHighThreshold" ]; then cHighThreshold="999"; fi

      if [ "$sen_err" == "" ] && [ "$value" -ge "$wLowThreshold" ] && [ "$value" -le "$wHighThreshold" ]
        then
            #summary+="${measurement} ${name}: ${value}${unit}. "
            details+="\n[OK] ${measurement} sensor ${name}: ${value}${unit} ${sen_err}"
        elif [ "$error_status" -gt 2 ] || [ "$value" -lt "$cLowThreshold" ] || [ "$value" -gt "$cHighThreshold" ]
          then
            (( crit++ ))
            summary+="${measurement} sensor ${name} value is ${value}${unit}! "
            details+="\n[CRITICAL] ${measurement} sensor ${name}: ${value}${unit} ${sen_err}"
            if [ "$value" -lt "$cLowThreshold" ]
              then
                details+="- Value is lower than allowed critical threshold. "
            elif [ "$value" -gt "$cHighThreshold" ]
              then
                details+="- Value is higher than allowed critical threshold. "
            fi
        else
            (( warn++ ))
            summary+="${measurement} sensor ${name} value is ${value}${unit}! "
            details+="\n[WARNING] ${measurement} sensor ${name}: ${value}${unit} ${sen_err}"
            if [ "$value" -lt "$wLowThreshold" ]
              then
                details+="- Value is lower than allowed warning threshold. "
            elif [ "$value" -gt "$wHighThreshold" ]
              then
                details+="- Value is higher than allowed warning threshold. "
            fi
      fi

  else
      (( warn++ ))
      summary+="${measurement} sensor ${name} has status ${comm_status_codes[$con_status]}! "
      details+="\n[WARNING] ${measurement} sensor ${name}: ${comm_status_codes[$con_status]}! "
  fi


done


if [ "$total_sensors" -eq 1 ]
  then
    summary="1 ${measurement} sensor detected. $summary"
  else
    summary="$total_sensors ${measurement} sensors detected. $summary"
fi

if [ "$crit" -gt 0 ]
  then
    summary="SNMP CRITICAL - ${summary}"
    exitCode=$codeCRITICAL
  elif [ "$warn" -gt 0 ]
    then
      summary="SNMP WARNING - ${summary}"
      exitCode=$codeWARNING
  else
    summary="SNMP OK - ${summary}All ${measurement} values are OK."
    exitCode=$codeOK
fi

printf "%s%b | %s\n" "$summary" "$details" "$perfdata"

exit $exitCode
