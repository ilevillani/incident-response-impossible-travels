# 🛡️ Investigation Report: Impossible Travel Logins  
*Date of Report: May 29, 2025*

---

## 🔍 1. Scheduled Analytics Rule

**Purpose:** Detect users signing in from geographically disparate locations within a time frame too short for physical travel (“impossible travel”).

### 🔍 1.1 KQL Query  
```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = 7d;
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count()
    by UserPrincipalName,
       AccountAadUserID = UserId,
       City    = tostring(parse_json(LocationDetails).city),
       State   = tostring(parse_json(LocationDetails).state),
       Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize PotentialImpossibleTravelInstances = count()
    by UserPrincipalName, AccountAadUserID
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

## 1.2 🗂️ MITRE ATT&CK Mapping  
| **Technique** | **Name**         | **Description**                                               |
|--------------:|------------------|---------------------------------------------------------------|
| **T1078**     | Valid Accounts   | Cloud accounts compromise via credential theft or misuse.     |

---

## 1.3 🔗 Entity Mapping  
| **Entity**         | **Identifier**      | **Column**             |
|--------------------|---------------------|------------------------|
| Account.Name       | `Account.Name`      | `UserPrincipalName`    |
| Account.AadUserID  | `Account.AadUserID` | `AccountAadUserID`     |

---

## 1.4 ⚙️ Rule Settings  
| **Setting**                           | **Value**                   |
|---------------------------------------|-----------------------------|
| 🔄 Alert Frequency                    | Every 5 hours               |
| ⏳ Lookup Window                      | Last 7 days                 |
| 🆕 Auto-create Incident               | ✔️                          |
| 📦 Group Alerts                       | Single incident per 24 hrs  |
| 🚫 Disable After First Alert (5-hr)   | ❌                          |
| ✅ Disable After First Alert (24-hr)  | ✔️                          |

---

## 🗃️ 2. Incident Work

### 2.1 🔍 Detection & Triage  
- **Total Alerts Generated:** 37  
- **Unique Accounts Flagged:** 37  
- **Accounts to Investigate:** 2

![image](https://github.com/user-attachments/assets/f37a2312-932e-457f-b342-2bc2a67b63c3)

![image](https://github.com/user-attachments/assets/f6978474-adbc-40e0-9698-ffc2d6fb3e10)


### 2.2 🚩 Flagged Accounts Overview  
Two accounts in particular look suspicious as they appear not to be from the IT Team which is required to travel:

| **UserPrincipalName**                                   | **GUID**                                | **Instances** |
|---------------------------------------------------------|-----------------------------------------|--------------:|
| `4891dd56...7eaa@lognpacific.com`                       | `c9f76850-ed5b-41d2-a97d-411916e0c84c`  |             6 |
| `eeb5d3da...7c7@lognpacific.com`                        | `10aa0da1-b6eb-47a0-9ecd-425d892d75eb`  |             5 |

---

## 🕵️‍♂️ 3. Detailed Investigation

Each individual account was investigated to see where they have been logging into and determine if they are true or false positives.

### 3.1 Account: `c9f76850-ed5b-41d2-a97d-411916e0c84c`  
**🔍 KQL Query:**  

```kql
let TimePeriodThreshold = 7d;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "4891dd56b0432e8134b2ece1b1c40661e84a97709cb9dc2d0910e8cbe9347eaa@lognpacific.com"
| project TimeGenerated,
          City    = tostring(parse_json(LocationDetails).city),
          State   = tostring(parse_json(LocationDetails).state),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**🗺️ Login Locations & Timeline:**  
- ✅ **May 27:** Silver Spring, MD → Boydton, VA (20 min apart)  
- Fairfax, VA  
- Greenbelt, MD  
- Seattle, WA  
- **May 23:** Ranson, WV  (1 hour approx. distance from the usual login location)

![image](https://github.com/user-attachments/assets/9f8ba012-22ed-49b5-b636-f6b522829d2d)


**🔎 Analysis:**  
- All logins within the U.S.  
- The distance between Silver Spring and Boydton requires approximately 3 hours of travel by car. However, the two locations are in the same country although in different States. It is still reasonable to think that the user might have connected to a Wi-Fi where the ISP was in a different State than the usual location of the user which appears to be Silver Spring, Maryland.

**✔️ Conclusion:**  
> **Benign / False Positive** – No further action required. Account left intact due to expected behaviour.

---

### 3.2 Account: `10aa0da1-b6eb-47a0-9ecd-425d892d75eb`  
**🔍 KQL Query:**  

```kql
let TimePeriodThreshold = 7d;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "eeb5d3da95689a0b777d86e0de3b2249137f3e56797825349376f183a79bd7c7@lognpacific.com"
| project TimeGenerated,
          City    = tostring(parse_json(LocationDetails).city),
          State   = tostring(parse_json(LocationDetails).state),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**🗺️ Login Locations & Timeline:**  
- McKinney, TX  
- Balaclava, Victoria, AU  
- Fitzroy, Victoria, AU  
- Burnside, Victoria, AU → Santa Clara, CA (2 hrs apart)  

![image](https://github.com/user-attachments/assets/c80ed1dd-be6f-4393-95de-d24160dd172d)


**🔎 Analysis:**  
- Impossible to travel ~12,000 km in 2 hrs.  
- High suspicion of credential compromise / VPN abuse.

**🔎 Supplemental AzureActivity Check:**  
Investigation in the AzureActivity log with target UserID to check what other activity the user has been doing:

```kql
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "10aa0da1-b6eb-47a0-9ecd-425d892d75eb"
```
- The logs did not show evidence of malicious activity carried by the user.

**⚠️ Conclusion:**  
> **True Positive** – Account compromise suspected. The user’s account was temporarily disabled in Entra ID and the user was contacted to investigate further. Management may also be informed.

---

## 🔒 4. Containment, Eradication & Recovery  

   - Disabled account `10aa0da1-…d7eb` in Entra ID  
   - Forced credential reset & MFA re-enrollment  
   - Notified user & management  

---

## 🔧 5. Post-Incident Activities  

- **Policy Updates:**  
  - Azure Conditional Access geo-fencing enabled  

- **Process Improvements:**  
  - SOC runbook updated with “Impossible Travel” playbook  

- **Training:**  
  - Briefed IT team on detection & response  

---

## ✅ 6. Incident Closure  

- Incident closed as **True Positive**  
- **Case Status:** Closed in Microsoft Sentinel with added notes within the incident details to document findings
