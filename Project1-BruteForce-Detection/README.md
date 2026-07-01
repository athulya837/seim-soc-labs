# Project 1: Brute Force Login Detection

## Objective
Detect brute force login attacks using Splunk SIEM 
by monitoring failed login attempts mapped to 
MITRE ATT&CK T1110.

## Tools Used
- Splunk Enterprise 10.4
- SPL (Search Processing Language)

## MITRE ATT&CK Mapping
- Technique: T1110 - Brute Force
- Tactic: Credential Access

## Detection Logic
Flags any source IP with more than 5 failed 
login attempts within a 10 minute window.

## SPL Query
| makeresults count=50
| streamstats count as row
| eval user=case(row<=20,"admin", 
  row<=35,"administrator", true(),"guest")
| eval src_ip=case(row<=20,"45.33.32.156", 
  row<=35,"192.168.1.105", true(),"10.0.0.22")
| eval EventCode="4625"
| eval _time=now()-(row*30)
| table _time, user, src_ip, EventCode
| stats count by src_ip, user
| where count > 5
| sort -count

## Findings
| src_ip | user | count | severity |
|---|---|---|---|
| 45.33.32.156 | admin | 20 | High |
| 10.0.0.22 | guest | 15 | Medium |
| 192.168.1.105 | administrator | 15 | Medium |

## Alert Configuration
- Schedule: Every 10 minutes
- Trigger: Results > 0
- Severity: High

## Screenshots
- Detection results (Statistics table)
- Saved alert
- SOC Brute Force Monitor dashboard
