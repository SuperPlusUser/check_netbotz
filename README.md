# check_netbotz
This repository contains two bash scripts for monitoring temperature, humidity and door sensors on NetBotz Rack Monitor devices via SNMP v2c or v3. The check plugins are developed for Icinga, but should also work for other (nagios based) monitoring tools. All connected wired sensors of the specified type are automatically detected and checked for compliance with the specified thresholds and for any alarms present on the NetBotz device. Performance data will also be generated based on the sensor values and thresholds.

Works with NetBotz devices using the PowerNet MIB (e.g. NetBotz 250) or NetBotz MIB (e.g. NetBotz 320E, 450). You can manually specify the MIB to use (see --mib option below). If you do not specify a MIB, the plugins try to automatically detect the device type.

Needs Net-SNMP Package installed. Tested with Ubuntu 18.04 and 20.04.

For installation, simply copy the two .sh files to `/usr/lib/nagios/plugins` (or whereevere your check plugins are stored) and make them executable.

## Temperature an humidity checks

```
Usage: check_netbotz_temp_humid.sh [OPTIONS]

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

Usage examples:
For SNMPv2:
check_netbotz_temp_humid.sh -H 10.10.10.10 -P 2c -C public -m powernet
For SNMPv3:
check_netbotz_temp_humid.sh -H 10.10.10.10 -P 3 -U icinga -a MD5 -A myAuthPzwD -x DES -X myPrivPw0d -m netbotz
```

## Door switch and dry contact input sensor checks

```
Usage: check_netbotz_door.sh [OPTIONS]

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
 -m      --mib               MIB to use. Possible values: powernet (e.g. used by NetBotz 250) or netbotz (e.g. used by NetBotz 320E and 450)
 -q      --help              Show this message
 -v      --version           Print version information and exit
```
