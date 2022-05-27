# check_netbotz
Monitoring plugins for Netbotz temperature, humidity and door sensors. Developed for Icinga, but should also work for other (nagios based) monitoring tools. Needs Net-SNMP Package installed. Tested with Ubuntu 18.04 and 20.04.

Works with Netbotz devices using the powernet mib (e.g. Netbotz 250) and netbotz mib (e.g. Netbotz 320E, 450). You can manually specify the mib to use (see --mib option below). If you do not specify a mib, the plugins try to automatically detect the device type.

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
 -A      --authpassword      SNMPv3 authentication password
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
check_netbotz_door.sh -H 10.10.10.10 -P 2c -C public -m powernet
For SNMPv3:
check_netbotz_door.sh -H 10.10.10.10 -P 3 -U icinga -a MD5 -A myAuthPzwD -x DES -X myPrivPw0d -m netbotz
```

## Door switch and dry contact input sensor checks

```
Usage: check_netbotz_temp_door.sh [OPTIONS]

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
```
