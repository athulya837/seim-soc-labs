# Project 1: Brute Force Login Detection Using Splunk

## 1. Introduction

Brute-force attacks involve repeated attempts to guess credentials to gain unauthorized access to an account or system. Security Operations Center (SOC) analysts review authentication events to identify unusual patterns, investigate potential credential attacks, and recommend appropriate response actions.

This project demonstrates a basic brute-force detection workflow using Splunk Enterprise and Search Processing Language (SPL). The current SPL example creates **synthetic test events** so the detection logic can be demonstrated without claiming that a real attack was observed.

## 2. Project Objectives

- Create test authentication events in Splunk.
- Use SPL to identify repeated failed login attempts.
- Group events by source IP address and account.
- Configure a scheduled alert.
- Present detection results in a Splunk dashboard.
- Map the detection use case to MITRE ATT&CK.
- Document findings, limitations, and possible responses.

## 3. Tools and Technologies

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise 10.4 |
| Query language | Search Processing Language (SPL) |
| Test data | Synthetic events generated using SPL |
| Detection use case | Repeated failed login attempts |
| ATT&CK mapping | T1110 – Brute Force |

> **Data note:** The supplied SPL uses `makeresults` and `eval` to generate artificial events. The IP addresses, usernames, event IDs, counts, and severity labels in the demonstration are test data, not proof of a real attack.

## 4. MITRE ATT&CK Mapping

- **Technique:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Tactic:** Credential Access

This mapping is relevant when activity indicates repeated attempts to guess credentials. Repeated failed logins alone do not confirm malicious activity; the analyst must assess context and supporting evidence.

## 5. Detection Logic

The intended detection use case is to identify a source IP address associated with more than five failed login attempts during a ten-minute period.

The investigation should consider:
- The number and timing of failed logins.
- The source IP address, if available.
- The account or accounts being targeted.
- Whether a successful login occurred near the failed attempts.
- Whether the activity can be explained by normal user behavior or a misconfigured service.

**Window clarification:** A query that groups events into ten-minute time buckets uses fixed windows. A continuously rolling ten-minute window requires different logic. The detection query should match the exact behavior described in the alert.

## 6. SPL Test Query

The following query generates 50 synthetic events, assigns usernames and source IP addresses, and counts events by IP and username.

```spl
| makeresults count=50
| streamstats count as row
| eval user=case(row<=20,"admin", row<=35,"administrator", true(),"guest")
| eval src_ip=case(row<=20,"45.33.32.156", row<=35,"192.168.1.105", true(),"10.0.0.22")
| eval EventCode="4625"
| eval _time=now()-(row*30)
| table _time, user, src_ip, EventCode
| stats count by src_ip, user
| where count > 5
| sort - count
```

### 6.1 Query Explanation

1. `makeresults count=50` creates 50 synthetic events.
2. `streamstats count as row` assigns each generated event a row number.
3. `eval user=case(...)` assigns the test usernames.
4. `eval src_ip=case(...)` assigns the test source IP addresses.
5. `eval EventCode="4625"` labels the generated events with the Windows failed-logon event ID.
6. `eval _time=now()-(row*30)` assigns timestamps 30 seconds apart.
7. `table` displays the timestamp, username, source IP, and event code.
8. `stats count by src_ip, user` counts events for each IP-and-user combination.
9. `where count > 5` retains combinations with more than five events.
10. `sort - count` sorts results from the largest count to the smallest.

**Important limitation:** This test query does not implement a ten-minute-window check. It also counts each source-IP-and-username combination separately, rather than aggregating all targeted usernames for each source IP. It is useful for demonstrating synthetic data generation and basic aggregation, but it should not be described as a validated ten-minute brute-force detector.

## 7. Example Test Results

The following are the expected group counts from the supplied synthetic query. Confirm the actual output in Splunk before publishing it as a screenshot.

| Source IP | Username | Event count |
|---|---|---:|
| 45.33.32.156 | admin | 20 |
| 192.168.1.105 | administrator | 15 |
| 10.0.0.22 | guest | 15 |

These counts represent generated test events. They do not establish that the listed addresses performed an attack. Do not infer maliciousness or assign severity based only on the count.

## 8. Example Search for Actual Windows Authentication Logs

When investigating actual Windows Security Event Logs, first confirm the correct Splunk index, sourcetype, and extracted field names. For example, if the index contains Windows events and the failed-logon event code is extracted as `EventCode`, a basic search may be:

```spl
index=<your_index> EventCode=4625
| table _time host user src_ip EventCode
| sort - _time
```

Replace `<your_index>` with the real index name and adjust fields to match your events. A missing result may mean that the index, field name, data source, or log collection configuration differs; it does not necessarily mean no failed logons occurred.

### Example: Fixed ten-minute buckets

After confirming the field names, this search groups failures by fixed ten-minute time buckets and source IP:

```spl
index=<your_index> EventCode=4625
| bin _time span=10m
| stats count as failed_attempts values(user) as targeted_users by _time src_ip
| where failed_attempts > 5
| sort - failed_attempts
```

This is a fixed-bucket example, not a continuously rolling ten-minute window. Validate it against the actual data and your detection requirements before enabling an alert. If the source IP field is absent or named differently, update the query accordingly.

## 9. Alert Configuration

Document the configuration used in your Splunk environment:

| Setting | Project configuration |
|---|---|
| Alert name | Brute Force Login Detection |
| Schedule | Every 10 minutes |
| Trigger condition | Number of results greater than zero |
| Alert severity | High (configured alert severity) |
| Search | Record the exact saved SPL search |
| Alert action | [Enter the action actually configured] |

The alert severity is a configuration setting; it does not automatically establish that every matching event is a high-severity incident. Use a documented severity rubric to classify findings, and distinguish alert severity from the analyst's assessment.

Also ensure the search's time range and schedule are appropriate. A scheduled search every ten minutes does not, by itself, guarantee that the search evaluates exactly a rolling ten-minute window.

## 10. Investigation Workflow

1. Run the search and verify that the results are based on the intended data source.
2. Check the timestamps, source IP, targeted account, and number of failed logons.
3. Determine whether multiple accounts are targeted by the same source.
4. Review successful logons around the same period, where the relevant logs are available.
5. Consider benign explanations, such as a user repeatedly entering the wrong password or a service using outdated credentials.
6. Record the evidence and state whether the assessment is benign, suspicious, or inconclusive.
7. Escalate according to the incident-response process if evidence supports a potential attack.

## 11. Screenshots and Evidence

Add screenshots from your own Splunk environment to the repository, for example:

- `screenshots/detection-results.png` — SPL search and returned results.
- `screenshots/saved-alert.png` — saved alert settings and schedule.
- `screenshots/dashboard.png` — brute-force monitoring dashboard.

Make sure screenshots match the claims in this document. Clearly label synthetic test results as simulated. Hide credentials, tokens, and unrelated sensitive information before publishing.

## 12. Findings

Complete this section based on what you verified in the lab.

| Item | Finding |
|---|---|
| Data used | Synthetic SPL events / actual authentication logs (specify) |
| Search tested | [Enter the exact SPL search] |
| Result count | [Enter the observed result count] |
| Time-window behavior validated | [Yes / No; explain] |
| Alert created and tested | [Yes / No] |
| Dashboard created and tested | [Yes / No] |
| Analyst assessment | [Benign / Suspicious / Inconclusive] |
| Evidence | [Link to screenshots or event references] |

### Findings summary

[Write a short, factual summary of what you observed. Do not describe generated test data as a real attack or claim that the detector works over a ten-minute window until that behavior has been tested.]

## 13. False Positives and Limitations

Potential benign causes of repeated failed logons include:
- Users entering incorrect passwords.
- Scheduled tasks or services using expired credentials.
- Applications repeatedly attempting authentication.
- Authorized security testing.

Limitations of this demonstration:
- The supplied query generates synthetic data.
- Its aggregation does not implement the stated ten-minute window.
- It groups by both IP address and username.
- The event fields may differ in real log sources.
- Event counts alone do not confirm an attack or successful compromise.

## 14. Recommended Response

If an investigation indicates suspicious authentication activity:

1. Preserve the relevant logs and timestamps.
2. Identify affected accounts, systems, and source addresses where available.
3. Correlate failures with successful logons and other endpoint activity.
4. Escalate according to the organization's procedures.
5. Consider controls such as multi-factor authentication, rate limiting, account protection, or blocking a source only after validating the evidence and operational impact.
6. Record the actions taken and the final disposition.

Do not disable accounts or block addresses solely because they appear in failed-login events without considering context and authorization.

## 15. Conclusion

This project demonstrates a starting workflow for brute-force detection using Splunk: generating test data, writing SPL searches, grouping authentication failures, configuring an alert, and documenting investigation results.

The synthetic query is useful for demonstrating SPL basics, but it must be improved and tested against the intended time-window logic before it can be described as a validated brute-force detector. A strong SOC portfolio distinguishes test data from real telemetry and supports conclusions with evidence.

## 16. Skills Demonstrated

- Splunk Enterprise and SPL fundamentals
- Authentication event analysis
- Basic detection logic
- Alert configuration
- Dashboard documentation
- MITRE ATT&CK mapping
- Evidence-based reporting
- False-positive awareness

## 17. References

- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- Microsoft Windows Event 4625 — Failed logon: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Windows Event 4624 — Successful logon: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- MITRE ATT&CK T1110 — Brute Force: https://attack.mitre.org/techniques/T1110/
