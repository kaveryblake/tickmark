/* Tickmark control library
 * Each topic is one evidence area. "m" maps it to control IDs in every supported framework,
 * which powers the per-framework list and the cross-framework "Also satisfies" view.
 * "e" lists evidence: [name, type, source template, isPopulationSample, ownerRoleOverride].
 * Source templates use {tokens} that resolve to the tools chosen during setup.
 */
"use strict";
const FW = {
  iso:{short:"ISO 27001",full:"ISO/IEC 27001:2022",blurb:"Annex A controls and ISMS clauses for certification and surveillance audits."},
  soc2:{short:"SOC 2",full:"SOC 2 (Trust Services Criteria)",blurb:"Common Criteria plus Availability and Confidentiality for Type I or Type II reports."},
  csf:{short:"NIST CSF",full:"NIST Cybersecurity Framework 2.0",blurb:"Govern, Identify, Protect, Detect, Respond, Recover outcomes for program assessments."},
  n53:{short:"NIST 800-53",full:"NIST SP 800-53 Rev. 5",blurb:"Moderate baseline control families for FedRAMP, FISMA, and agency assessments."},
  cmmc:{short:"CMMC L2",full:"CMMC 2.0 Level 2",blurb:"NIST SP 800-171 practices for protecting CUI on DoD contracts."},
  pci:{short:"PCI DSS",full:"PCI DSS v4.0.1",blurb:"Requirements for environments that store, process, or transmit cardholder data."},
  hipaa:{short:"HIPAA",full:"HIPAA Security Rule",blurb:"Administrative, physical, and technical safeguards for ePHI."}
};
const FW_ORDER=["iso","soc2","csf","n53","cmmc","pci","hipaa"];

const NAMES = {
 iso:{"5.1":"Policies for information security","5.2":"Information security roles and responsibilities","5.9":"Inventory of information and other associated assets","5.12":"Classification of information","5.15":"Access control","5.18":"Access rights","5.19":"Information security in supplier relationships","5.22":"Monitoring, review and change management of supplier services","5.24":"Incident management planning and preparation","5.26":"Response to information security incidents","5.30":"ICT readiness for business continuity","6.1":"Screening","6.3":"Information security awareness, education and training","6.5":"Responsibilities after termination or change of employment","6.7":"Remote working","7.2":"Physical entry","7.14":"Secure disposal or re-use of equipment","8.2":"Privileged access rights","8.5":"Secure authentication","8.7":"Protection against malware","8.8":"Management of technical vulnerabilities","8.9":"Configuration management","8.10":"Information deletion","8.13":"Information backup","8.15":"Logging","8.16":"Monitoring activities","8.20":"Networks security","8.24":"Use of cryptography","8.25":"Secure development life cycle","8.28":"Secure coding","8.32":"Change management","Cl.4.3":"Determining the scope of the ISMS","Cl.6.1.2":"Information security risk assessment","Cl.9.2":"Internal audit","Cl.10.2":"Nonconformity and corrective action"},
 soc2:{"CC1.3":"Establishes structures, reporting lines, and responsibilities","CC1.4":"Demonstrates commitment to competence","CC2.2":"Internally communicates security information","CC3.2":"Identifies and analyzes risk","CC4.1":"Performs ongoing and separate evaluations","CC4.2":"Evaluates and communicates deficiencies","CC5.3":"Deploys controls through policies and procedures","CC6.1":"Logical access security measures","CC6.2":"User registration and authorization","CC6.3":"Role-based access, modification, and removal","CC6.4":"Restricts physical access","CC6.5":"Discontinues protections over disposed assets","CC6.6":"Protects against threats outside system boundaries","CC6.7":"Restricts transmission of information","CC6.8":"Prevents or detects malicious software","CC7.1":"Detects configuration changes and vulnerabilities","CC7.2":"Monitors system components for anomalies","CC7.3":"Evaluates security events","CC7.4":"Responds to security incidents","CC8.1":"Manages changes to infrastructure and software","CC9.2":"Assesses and manages vendor risk","A1.2":"Backup and recovery infrastructure","A1.3":"Tests recovery plan procedures","C1.1":"Identifies and maintains confidential information","C1.2":"Disposes of confidential information","DC200":"System description (Description Criteria)"},
 csf:{"GV.PO-01":"Cybersecurity risk policy is established and communicated","GV.RR-02":"Roles, responsibilities, and authorities are established","GV.RR-04":"Cybersecurity is included in HR practices","GV.RM-01":"Risk management objectives are established","GV.SC-07":"Supplier risks are assessed and monitored","ID.AM-01":"Hardware inventories are maintained","ID.AM-02":"Software and service inventories are maintained","ID.AM-03":"Network communication and data flows are documented","ID.AM-07":"Data inventories are maintained","ID.AM-08":"Assets and data are managed through their life cycles","ID.RA-01":"Vulnerabilities are identified and recorded","ID.RA-05":"Threats, likelihood, and impact inform inherent risk","ID.RA-07":"Changes and exceptions are managed and tracked","ID.IM-01":"Improvements are identified from evaluations","ID.IM-02":"Improvements are identified from tests and exercises","PR.AA-01":"Identities and credentials are managed","PR.AA-03":"Users, services, and hardware are authenticated","PR.AA-05":"Access permissions are managed with least privilege","PR.AA-06":"Physical access is managed and monitored","PR.AT-01":"Personnel receive awareness and training","PR.DS-01":"Data at rest is protected","PR.DS-02":"Data in transit is protected","PR.DS-11":"Backups are created, protected, and tested","PR.PS-01":"Configuration management practices are applied","PR.PS-02":"Software is maintained commensurate with risk","PR.PS-04":"Log records are generated for monitoring","PR.PS-06":"Secure software development practices are integrated","PR.IR-01":"Networks are protected from unauthorized access","DE.CM-01":"Networks and network services are monitored","DE.CM-09":"Computing hardware and software are monitored","RS.MA-01":"Incident response plan is executed","RC.RP-01":"Recovery plan is executed"},
 n53:{"PL-1":"Policy and Procedures","PM-1":"Information Security Program Plan","PM-2":"Information Security Program Leadership Role","PL-2":"System Security and Privacy Plans","RA-2":"Security Categorization","RA-3":"Risk Assessment","RA-5":"Vulnerability Monitoring and Scanning","CA-2":"Control Assessments","CA-5":"Plan of Action and Milestones","CA-7":"Continuous Monitoring","CM-2":"Baseline Configuration","CM-3":"Configuration Change Control","CM-6":"Configuration Settings","CM-8":"System Component Inventory","AC-2":"Account Management","AC-6":"Least Privilege","AC-7":"Unsuccessful Logon Attempts","AC-11":"Device Lock","AC-17":"Remote Access","IA-2(1)":"MFA to Privileged Accounts","IA-2(2)":"MFA to Non-privileged Accounts","PS-3":"Personnel Screening","PS-4":"Personnel Termination","AT-2":"Literacy Training and Awareness","SI-2":"Flaw Remediation","SI-3":"Malicious Code Protection","SI-4":"System Monitoring","AU-2":"Event Logging","AU-6":"Audit Record Review, Analysis, and Reporting","AU-11":"Audit Record Retention","SC-7":"Boundary Protection","SC-8":"Transmission Confidentiality and Integrity","SC-28":"Protection of Information at Rest","SA-9":"External System Services","SA-11":"Developer Testing and Evaluation","SR-6":"Supplier Assessments and Reviews","IR-3":"Incident Response Testing","IR-4":"Incident Handling","IR-8":"Incident Response Plan","CP-2":"Contingency Plan","CP-4":"Contingency Plan Testing","CP-9":"System Backup","PE-2":"Physical Access Authorizations","PE-3":"Physical Access Control","PE-8":"Visitor Access Records","MP-6":"Media Sanitization"},
 pci:{"12.1.1": "Information security policy is established, published, maintained, and disseminated", "12.1.2": "Information security policy is reviewed at least annually", "12.1.3": "Security roles and responsibilities are defined and acknowledged", "12.1.4": "Responsibility for information security is assigned to an executive", "12.5.2": "PCI DSS scope is documented and confirmed at least annually", "1.2.3": "Accurate network diagram is maintained", "1.2.4": "Accurate data-flow diagram is maintained", "12.3.1": "Targeted risk analysis is performed for flexible requirements", "12.4.2": "Reviews confirm personnel perform security tasks (service providers)", "12.6.1": "Formal security awareness program is implemented", "12.6.3": "Personnel receive training upon hire and at least annually", "12.6.3.1": "Training covers phishing and social engineering", "12.7.1": "Potential personnel with CDE access are screened", "7.2.1": "Access control model is defined", "7.2.2": "Access is assigned based on job classification and least privilege", "7.2.4": "User accounts and access privileges are reviewed at least every six months", "8.2.4": "Additions, deletions, and modifications of user IDs are authorized", "8.2.5": "Access for terminated users is immediately revoked", "8.4.1": "MFA for all non-console administrative access into the CDE", "8.4.2": "MFA for all access into the CDE", "8.4.3": "MFA for all remote network access", "8.2.8": "Sessions idle more than 15 minutes require reauthentication", "8.3.4": "Accounts lock after no more than 10 failed attempts", "12.5.1": "Inventory of in-scope system components is maintained", "6.3.2": "Inventory of bespoke and custom software is maintained", "2.2.1": "Configuration standards are developed and implemented", "5.2.1": "Anti-malware solution is deployed on system components", "5.3.1": "Anti-malware solution is kept current", "6.3.1": "Security vulnerabilities are identified and ranked", "11.3.1": "Internal vulnerability scans are performed at least quarterly", "11.3.2": "External ASV scans are performed at least quarterly", "6.3.3": "Critical patches are installed within one month of release", "1.2.7": "NSC configurations are reviewed at least every six months", "1.3.1": "Inbound traffic to the CDE is restricted", "10.2.1": "Audit logs are enabled and active for all system components", "10.5.1": "Audit log history is retained for at least 12 months", "10.4.1": "Security events and critical logs are reviewed at least daily", "11.5.1": "Intrusion detection or prevention techniques are used", "9.4.2": "Media with cardholder data is classified", "3.5.1": "PAN is rendered unreadable wherever it is stored", "4.2.1": "Strong cryptography protects PAN during transmission over public networks", "3.2.1": "Account data storage is kept to a minimum through retention and disposal", "9.4.7": "Media is destroyed when no longer needed", "6.5.1": "Changes to system components follow change control", "6.2.1": "Bespoke and custom software is developed securely", "6.2.3": "Bespoke and custom software is reviewed before release", "12.8.1": "List of third-party service providers is maintained", "12.8.2": "Written agreements with TPSPs are maintained", "12.8.4": "TPSP PCI DSS compliance status is monitored at least annually", "12.10.1": "Incident response plan exists and is ready to be activated", "12.10.2": "Incident response plan is reviewed and tested at least annually", "9.2.1": "Facility entry controls restrict physical access to the CDE", "9.3.1": "Personnel physical access to sensitive areas is authorized", "9.3.2": "Visitor access to the CDE is authorized and escorted", "9.3.4": "Visitor log is maintained"},
 hipaa:{"164.316(a)": "Policies and procedures", "164.316(b)(1)": "Documentation", "164.308(a)(2)": "Assigned security responsibility", "164.308(a)(1)(ii)(A)": "Risk analysis (Required)", "164.308(a)(1)(ii)(B)": "Risk management (Required)", "164.308(a)(1)(ii)(D)": "Information system activity review (Required)", "164.308(a)(8)": "Evaluation", "164.308(a)(5)(i)": "Security awareness and training", "164.308(a)(5)(ii)(B)": "Protection from malicious software (Addressable)", "164.308(a)(5)(ii)(C)": "Log-in monitoring (Addressable)", "164.308(a)(5)(ii)(D)": "Password management (Addressable)", "164.308(a)(3)(ii)(B)": "Workforce clearance procedure (Addressable)", "164.308(a)(3)(ii)(C)": "Termination procedures (Addressable)", "164.308(a)(4)(ii)(B)": "Access authorization (Addressable)", "164.308(a)(4)(ii)(C)": "Access establishment and modification (Addressable)", "164.308(a)(6)": "Security incident procedures", "164.308(a)(7)(ii)(A)": "Data backup plan (Required)", "164.308(a)(7)(ii)(B)": "Disaster recovery plan (Required)", "164.308(a)(7)(ii)(D)": "Testing and revision procedures (Addressable)", "164.308(b)(1)": "Business associate contracts", "164.314(a)": "Business associate contract requirements", "164.310(a)(1)": "Facility access controls", "164.310(a)(2)(iii)": "Access control and validation procedures (Addressable)", "164.310(d)(2)(i)": "Disposal (Required)", "164.310(d)(2)(ii)": "Media re-use (Required)", "164.310(d)(2)(iii)": "Accountability (Addressable)", "164.312(a)(1)": "Access control", "164.312(a)(2)(iii)": "Automatic logoff (Addressable)", "164.312(a)(2)(iv)": "Encryption and decryption (Addressable)", "164.312(b)": "Audit controls", "164.312(d)": "Person or entity authentication", "164.312(e)(1)": "Transmission security", "164.312(e)(2)(ii)": "Encryption in transmission (Addressable)"},
 cmmc:{"AC.L2-3.1.1":"Authorized Access Control","AC.L2-3.1.5":"Least Privilege","AC.L2-3.1.8":"Unsuccessful Logon Attempts","AC.L2-3.1.10":"Session Lock","AC.L2-3.1.12":"Control Remote Access","AT.L2-3.2.1":"Role-Based Risk Awareness","AU.L2-3.3.1":"System Auditing","AU.L2-3.3.5":"Audit Correlation","CM.L2-3.4.1":"System Baselining","CM.L2-3.4.2":"Security Configuration Enforcement","CM.L2-3.4.3":"System Change Management","IA.L2-3.5.3":"Multifactor Authentication","IR.L2-3.6.1":"Incident Handling","IR.L2-3.6.3":"Incident Response Testing","MP.L2-3.8.3":"Media Disposal","MP.L2-3.8.4":"Media Markings","MP.L2-3.8.9":"Protect Backups","PS.L2-3.9.1":"Screen Individuals","PS.L2-3.9.2":"Personnel Actions","PE.L2-3.10.1":"Limit Physical Access","PE.L2-3.10.3":"Escort Visitors","RA.L2-3.11.1":"Risk Assessments","RA.L2-3.11.2":"Vulnerability Scan","CA.L2-3.12.1":"Security Control Assessment","CA.L2-3.12.2":"Plan of Action","CA.L2-3.12.3":"Security Control Monitoring","CA.L2-3.12.4":"System Security Plan","SC.L2-3.13.1":"Boundary Protection","SC.L2-3.13.8":"Data in Transit","SC.L2-3.13.16":"Data at Rest","SI.L2-3.14.1":"Flaw Remediation","SI.L2-3.14.2":"Malicious Code Protection","SI.L2-3.14.6":"Monitor Communications for Attacks"}
};
function idLabel(fw,id){ if(fw==="hipaa") return "\u00a7"+id; if(fw==="iso") return id.startsWith("Cl.")?id.replace("Cl.","Clause "):"A."+id; return id==="DC200"?"DC 200":id; }

const DOMAINS = [
 ["governance","Governance & risk","Policies, scope, risk register, internal audit"],
 ["people","People & training","Screening, awareness training"],
 ["identity","Identity & access","Provisioning, reviews, MFA, privileged access"],
 ["endpoints","Assets & endpoints","Inventory, baselines, EDR, vulnerabilities, patching"],
 ["network","Network & monitoring","Firewalls, remote access, logging, alerting"],
 ["data","Data protection","Classification, encryption, retention, disposal"],
 ["change","Change & development","Change control, SDLC, code review"],
 ["vendors","Third parties","Vendor inventory, assessments, contracts"],
 ["incident","Incident response","IR plan, incident log, tabletop exercises"],
 ["continuity","Backup & continuity","Backups, restore tests, BC/DR"],
 ["physical","Physical security","Badge access, visitors, data center reports"]
];
const DNAME = Object.fromEntries(DOMAINS.map(d=>[d[0],d[1]]));

/* evidence: [name, type, source, sample?, ownerOverride?] */
const TOPICS = [
 {id:"policy",d:"governance",t:"Information security policy",o:"comp",m:{iso:["5.1"],soc2:["CC5.3"],csf:["GV.PO-01"],n53:["PL-1","PM-1"],cmmc:[],pci:["12.1.1", "12.1.2"],hipaa:["164.316(a)", "164.316(b)(1)"]},e:[
  ["Information security policy, current version with approval signature and date","Document","{docs} policy library"],
  ["Evidence of annual policy review (version history or review log)","Record","{docs} version history"],
  ["Employee policy acknowledgments","Sample set","{hris} acknowledgment report",1,"hr"]]},
 {id:"roles",d:"governance",t:"Security roles and reporting lines",o:"exec",m:{iso:["5.2"],soc2:["CC1.3"],csf:["GV.RR-02"],n53:["PM-2"],cmmc:[],pci:["12.1.3", "12.1.4"],hipaa:["164.308(a)(2)"]},e:[
  ["Org chart showing security reporting lines","Document","{hris} org chart export","","hr"],
  ["Security roles and responsibilities matrix (RACI)","Document","{docs}"]]},
 {id:"scope",d:"governance",t:"System scope and boundary",o:"comp",m:{iso:["Cl.4.3"],soc2:["DC200"],csf:["ID.AM-03"],n53:["PL-2"],cmmc:["CA.L2-3.12.4"],pci:["12.5.2", "1.2.3", "1.2.4"],hipaa:[]},e:[
  ["Scope document (ISMS scope and SoA, SOC 2 system description, or SSP)","Document","{docs}"],
  ["Network and data flow diagrams for in-scope systems","Document","{docs}; {cloud} architecture diagrams","","it"]]},
 {id:"risk",d:"governance",t:"Risk assessment",o:"comp",m:{iso:["Cl.6.1.2"],soc2:["CC3.2"],csf:["ID.RA-05","GV.RM-01"],n53:["RA-3"],cmmc:["RA.L2-3.11.1"],pci:["12.3.1"],hipaa:["164.308(a)(1)(ii)(A)", "164.308(a)(1)(ii)(B)"]},e:[
  ["Risk assessment methodology (rating scales, appetite, criteria)","Document","{docs}"],
  ["Current risk register with owners, ratings, and treatment decisions","Record","Risk register in {docs}"],
  ["Leadership sign-off on risk treatment and accepted risks","Record","Meeting minutes or approval records","","exec"]]},
 {id:"audit",d:"governance",t:"Internal audit and control monitoring",o:"comp",m:{iso:["Cl.9.2"],soc2:["CC4.1"],csf:["ID.IM-01"],n53:["CA-2","CA-7"],cmmc:["CA.L2-3.12.1","CA.L2-3.12.3"],pci:["12.4.2"],hipaa:["164.308(a)(8)"]},e:[
  ["Internal audit or control assessment plan","Document","{docs}"],
  ["Most recent internal audit report with findings","Record","{docs}"],
  ["Continuous monitoring results or control test log","System report","{siem} dashboards; {docs}"]]},
 {id:"poam",d:"governance",t:"Corrective actions and POA&M",o:"comp",m:{iso:["Cl.10.2"],soc2:["CC4.2"],csf:["ID.IM-01"],n53:["CA-5"],cmmc:["CA.L2-3.12.2"],pci:[],hipaa:["164.308(a)(1)(ii)(B)"]},e:[
  ["Corrective action log or POA&M with owners and target dates","Record","{ticket} or {docs}"],
  ["Closure evidence for remediated findings","Sample set","{ticket} closed items",1]]},
 {id:"training",d:"people",t:"Security awareness training",o:"hr",m:{iso:["6.3"],soc2:["CC2.2","CC1.4"],csf:["PR.AT-01"],n53:["AT-2"],cmmc:["AT.L2-3.2.1"],pci:["12.6.1", "12.6.3", "12.6.3.1"],hipaa:["164.308(a)(5)(i)"]},e:[
  ["Training content and annual schedule","Document","{lms} campaign settings"],
  ["Training completion report for all personnel","System report","{lms} completion report"],
  ["Phishing simulation results","System report","{lms} phishing reports","","sec"]]},
 {id:"screening",d:"people",t:"Background screening",o:"hr",m:{iso:["6.1"],soc2:["CC1.4"],csf:["GV.RR-04"],n53:["PS-3"],cmmc:["PS.L2-3.9.1"],pci:["12.7.1"],hipaa:["164.308(a)(3)(ii)(B)"]},e:[
  ["Background check procedure","Document","{docs}"],
  ["Background check completion for new hires","Sample set","{hris} onboarding records",1]]},
 {id:"prov",d:"identity",t:"Access provisioning",o:"iam",m:{iso:["5.15","5.18"],soc2:["CC6.2"],csf:["PR.AA-01"],n53:["AC-2"],cmmc:["AC.L2-3.1.1"],pci:["7.2.1", "8.2.4"],hipaa:["164.308(a)(4)(ii)(B)", "164.312(a)(1)"]},e:[
  ["Access control policy","Document","{docs}","","comp"],
  ["Current list of active user accounts","System report","{idp} user export"],
  ["New access requests with manager approval before provisioning","Sample set","{ticket} access request tickets",1]]},
 {id:"review",d:"identity",t:"User access reviews",o:"iam",m:{iso:["5.18"],soc2:["CC6.2","CC6.3"],csf:["PR.AA-05"],n53:["AC-2"],cmmc:["AC.L2-3.1.1"],pci:["7.2.4"],hipaa:["164.308(a)(4)(ii)(C)"]},e:[
  ["Completed user access reviews with reviewer sign-off","Record","{idp} access reviews or review workbook",1],
  ["Tickets showing removal of access flagged during review","Sample set","{ticket}",1]]},
 {id:"term",d:"identity",t:"Termination and deprovisioning",o:"iam",m:{iso:["6.5"],soc2:["CC6.2"],csf:["PR.AA-01"],n53:["PS-4"],cmmc:["PS.L2-3.9.2"],pci:["8.2.5"],hipaa:["164.308(a)(3)(ii)(C)"]},e:[
  ["Terminated personnel list for the period","System report","{hris} termination report",1,"hr"],
  ["Account disable timestamps matched to termination dates","Sample set","{idp} audit log",1]]},
 {id:"mfa",d:"identity",t:"Multi-factor authentication",o:"iam",m:{iso:["8.5"],soc2:["CC6.1"],csf:["PR.AA-03"],n53:["IA-2(1)","IA-2(2)"],cmmc:["IA.L2-3.5.3"],pci:["8.4.1", "8.4.2"],hipaa:["164.312(d)"]},e:[
  ["MFA enforcement policy configuration","Screenshot","{idp} authentication policies"],
  ["MFA enrollment report for all users, with exceptions explained","System report","{idp} MFA registration report"]]},
 {id:"authn",d:"identity",t:"Password, lockout, and session settings",o:"iam",m:{iso:["8.5"],soc2:["CC6.1"],csf:["PR.AA-03"],n53:["AC-7","AC-11"],cmmc:["AC.L2-3.1.8","AC.L2-3.1.10"],pci:["8.3.4", "8.2.8"],hipaa:["164.308(a)(5)(ii)(D)", "164.312(a)(2)(iii)"]},e:[
  ["Password and account lockout settings","Screenshot","{idp} password policy"],
  ["Screen lock and session timeout configuration","Screenshot","{mdm} device configuration profile","","it"]]},
 {id:"priv",d:"identity",t:"Privileged access",o:"iam",m:{iso:["8.2"],soc2:["CC6.3"],csf:["PR.AA-05"],n53:["AC-6"],cmmc:["AC.L2-3.1.5"],pci:["7.2.2"],hipaa:["164.312(a)(1)"]},e:[
  ["List of privileged and admin accounts with business justification","System report","{idp} admin roles; {cloud} IAM roles"],
  ["Privileged access review sign-off","Record","{docs}",1]]},
 {id:"assets",d:"endpoints",t:"Asset inventory",o:"it",m:{iso:["5.9"],soc2:["CC6.1"],csf:["ID.AM-01","ID.AM-02"],n53:["CM-8"],cmmc:["CM.L2-3.4.1"],pci:["12.5.1", "6.3.2"],hipaa:["164.310(d)(2)(iii)"]},e:[
  ["Hardware asset inventory with assigned owners","System report","{mdm} device inventory"],
  ["Software and cloud resource inventory","System report","{cloud} resource inventory; {mdm} app inventory"]]},
 {id:"baseline",d:"endpoints",t:"Secure configuration baselines",o:"it",m:{iso:["8.9"],soc2:["CC7.1"],csf:["PR.PS-01"],n53:["CM-2","CM-6"],cmmc:["CM.L2-3.4.2"],pci:["2.2.1"],hipaa:[]},e:[
  ["Approved hardening standards (for example, CIS Benchmarks)","Document","{docs}"],
  ["Configuration compliance report against the baseline","System report","{cloudcfg}; {mdm} compliance policies"]]},
 {id:"malware",d:"endpoints",t:"Malware protection",o:"sec",m:{iso:["8.7"],soc2:["CC6.8"],csf:["DE.CM-09"],n53:["SI-3"],cmmc:["SI.L2-3.14.2"],pci:["5.2.1", "5.3.1"],hipaa:["164.308(a)(5)(ii)(B)"]},e:[
  ["EDR coverage report reconciled to the asset inventory","System report","{edr} host management"],
  ["EDR prevention policy (real-time and tamper protection)","Screenshot","{edr} prevention policies"]]},
 {id:"vuln",d:"endpoints",t:"Vulnerability scanning",o:"sec",m:{iso:["8.8"],soc2:["CC7.1"],csf:["ID.RA-01"],n53:["RA-5"],cmmc:["RA.L2-3.11.2"],pci:["6.3.1", "11.3.1", "11.3.2"],hipaa:["164.308(a)(1)(ii)(B)"]},e:[
  ["Vulnerability management procedure with remediation SLAs","Document","{docs}"],
  ["Scan schedule and target scope configuration","Screenshot","{vuln} scan configuration"],
  ["Scan results across the period","Sample set","{vuln} reports",1]]},
 {id:"patch",d:"endpoints",t:"Patching and flaw remediation",o:"it",m:{iso:["8.8"],soc2:["CC7.1"],csf:["PR.PS-02"],n53:["SI-2"],cmmc:["SI.L2-3.14.1"],pci:["6.3.3"],hipaa:["164.308(a)(1)(ii)(B)"]},e:[
  ["Patch compliance report","System report","{mdm} update compliance"],
  ["Critical vulnerability tickets closed within SLA","Sample set","{ticket}",1]]},
 {id:"remote",d:"network",t:"Remote access",o:"it",m:{iso:["6.7"],soc2:["CC6.6"],csf:["PR.IR-01"],n53:["AC-17"],cmmc:["AC.L2-3.1.12"],pci:["8.4.3"],hipaa:["164.312(e)(1)"]},e:[
  ["Remote work and remote access policy","Document","{docs}","","comp"],
  ["VPN or ZTNA configuration showing MFA and session controls","Screenshot","VPN or ZTNA admin console"]]},
 {id:"netsec",d:"network",t:"Network boundary protection",o:"it",m:{iso:["8.20"],soc2:["CC6.6"],csf:["PR.IR-01"],n53:["SC-7"],cmmc:["SC.L2-3.13.1"],pci:["1.2.7", "1.3.1"],hipaa:["164.312(e)(1)"]},e:[
  ["Firewall and security group rule export","Config export","{fw}"],
  ["Firewall rule review sign-off","Record","{ticket} or {docs}",1]]},
 {id:"logging",d:"network",t:"Audit logging",o:"sec",m:{iso:["8.15"],soc2:["CC7.2"],csf:["PR.PS-04"],n53:["AU-2","AU-11"],cmmc:["AU.L2-3.3.1"],pci:["10.2.1", "10.5.1"],hipaa:["164.312(b)"]},e:[
  ["Audit logging enabled on in-scope systems","Screenshot","{cloudlog}; {idp} sign-in logs"],
  ["Log retention settings","Config export","{siem} retention settings"]]},
 {id:"monitor",d:"network",t:"Security monitoring and alerting",o:"sec",m:{iso:["8.16"],soc2:["CC7.2"],csf:["DE.CM-01"],n53:["SI-4","AU-6"],cmmc:["SI.L2-3.14.6","AU.L2-3.3.5"],pci:["10.4.1", "11.5.1"],hipaa:["164.308(a)(1)(ii)(D)", "164.308(a)(5)(ii)(C)"]},e:[
  ["Enabled detection rules and alert routing","Config export","{siem} analytics rules"],
  ["Alerts with triage notes and resolution","Sample set","{siem} incidents; {ticket}",1]]},
 {id:"classify",d:"data",t:"Data classification",o:"comp",m:{iso:["5.12"],soc2:["C1.1"],csf:["ID.AM-07"],n53:["RA-2"],cmmc:["MP.L2-3.8.4"],pci:["9.4.2"],hipaa:[]},e:[
  ["Data classification policy and labeling scheme","Document","{docs}"],
  ["Inventory of in-scope data stores with classification","Record","{docs}; {cloud} resource tags","","it"]]},
 {id:"crypto",d:"data",t:"Encryption at rest and in transit",o:"sec",m:{iso:["8.24"],soc2:["CC6.1","CC6.7"],csf:["PR.DS-01","PR.DS-02"],n53:["SC-28","SC-8"],cmmc:["SC.L2-3.13.16","SC.L2-3.13.8"],pci:["3.5.1", "4.2.1"],hipaa:["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"]},e:[
  ["Encryption at rest for databases and storage","Config export","{kms}; storage encryption settings"],
  ["TLS configuration for external endpoints","Screenshot","Load balancer and certificate settings"],
  ["Full-disk encryption compliance for laptops","System report","{mdm} encryption report","","it"]]},
 {id:"disposal",d:"data",t:"Retention and secure disposal",o:"it",m:{iso:["8.10","7.14"],soc2:["C1.2","CC6.5"],csf:["ID.AM-08"],n53:["MP-6"],cmmc:["MP.L2-3.8.3"],pci:["3.2.1", "9.4.7"],hipaa:["164.310(d)(2)(i)", "164.310(d)(2)(ii)"]},e:[
  ["Data retention and disposal standard","Document","{docs}","","comp"],
  ["Wipe records or certificates of destruction","Sample set","{mdm} wipe log; disposal vendor certificates",1]]},
 {id:"change",d:"change",t:"Change management",o:"eng",m:{iso:["8.32"],soc2:["CC8.1"],csf:["ID.RA-07"],n53:["CM-3"],cmmc:["CM.L2-3.4.3"],pci:["6.5.1"],hipaa:[]},e:[
  ["Change management procedure","Document","{docs}"],
  ["Change tickets with approval, testing, and deployment evidence","Sample set","{ticket} change records",1],
  ["Branch protection or deployment approval settings","Screenshot","{vcs} repository settings"]]},
 {id:"sdlc",d:"change",t:"Secure development",o:"eng",m:{iso:["8.25","8.28"],soc2:["CC8.1"],csf:["PR.PS-06"],n53:["SA-11"],cmmc:[],pci:["6.2.1", "6.2.3"],hipaa:[]},e:[
  ["Secure development standard","Document","{docs}"],
  ["Pull requests showing peer review before merge","Sample set","{vcs} merged pull requests",1],
  ["SAST or dependency scan results from CI","System report","{vcs} pipeline results"]]},
 {id:"vendor",d:"vendors",t:"Third-party risk management",o:"proc",m:{iso:["5.19","5.22"],soc2:["CC9.2"],csf:["GV.SC-07"],n53:["SA-9","SR-6"],cmmc:[],pci:["12.8.1", "12.8.2", "12.8.4"],hipaa:["164.308(b)(1)", "164.314(a)"]},e:[
  ["Third-party risk management procedure","Document","{docs}"],
  ["Vendor inventory with risk tiers","Record","Vendor register in {docs}"],
  ["Assessments for critical vendors (SOC 2 reports, questionnaires)","Sample set","{docs} vendor files",1],
  ["Contracts showing security and confidentiality terms","Sample set","Contract repository",1]]},
 {id:"irplan",d:"incident",t:"Incident response",o:"sec",m:{iso:["5.24","5.26"],soc2:["CC7.3","CC7.4"],csf:["RS.MA-01"],n53:["IR-8","IR-4"],cmmc:["IR.L2-3.6.1"],pci:["12.10.1"],hipaa:["164.308(a)(6)"]},e:[
  ["Incident response plan with roles and escalation paths","Document","{docs}"],
  ["Security incident log or tickets for the period","Sample set","{ticket} security incidents",1]]},
 {id:"irtest",d:"incident",t:"Incident response testing",o:"sec",m:{iso:["5.24"],soc2:["CC7.4"],csf:["ID.IM-02"],n53:["IR-3"],cmmc:["IR.L2-3.6.3"],pci:["12.10.2"],hipaa:[]},e:[
  ["Tabletop exercise report with attendees and lessons learned","Record","{docs}"]]},
 {id:"backup",d:"continuity",t:"Backups and restore testing",o:"it",m:{iso:["8.13"],soc2:["A1.2"],csf:["PR.DS-11"],n53:["CP-9"],cmmc:["MP.L2-3.8.9"],pci:[],hipaa:["164.308(a)(7)(ii)(A)"]},e:[
  ["Backup policy and job schedule configuration","Screenshot","{backup}"],
  ["Backup job success history","Sample set","{backup} job history",1],
  ["Restore test results","Record","{ticket} or {docs}"]]},
 {id:"bcp",d:"continuity",t:"Business continuity and disaster recovery",o:"it",m:{iso:["5.30"],soc2:["A1.3"],csf:["RC.RP-01"],n53:["CP-2","CP-4"],cmmc:[],pci:[],hipaa:["164.308(a)(7)(ii)(B)", "164.308(a)(7)(ii)(D)"]},e:[
  ["BC/DR plan with RTO and RPO targets","Document","{docs}","","exec"],
  ["DR test report with actual recovery times","Record","{docs}"]]},
 {id:"physical",d:"physical",t:"Physical access",o:"fac",m:{iso:["7.2"],soc2:["CC6.4"],csf:["PR.AA-06"],n53:["PE-2","PE-3","PE-8"],cmmc:["PE.L2-3.10.1","PE.L2-3.10.3"],pci:["9.2.1", "9.3.1", "9.3.2", "9.3.4"],hipaa:["164.310(a)(1)", "164.310(a)(2)(iii)"]},e:[
  ["Badge access list for secure areas","System report","Badge system export"],
  ["Visitor logs with escort records","Sample set","Front desk visitor system",1],
  ["Data center or cloud provider SOC 2 report","Document","{cloudportal}","","comp"]]}
];

const STACK = {
 cloud:{label:"Hosting",opts:{azure:"Azure",aws:"AWS",gcp:"Google Cloud",onprem:"On-premises"}},
 idp:{label:"Identity provider",opts:["Microsoft Entra ID","Okta","Google Workspace","Active Directory"]},
 ticket:{label:"Ticketing",opts:["ServiceNow","Jira","Freshservice"]},
 edr:{label:"Endpoint protection",opts:["Microsoft Defender for Endpoint","CrowdStrike Falcon","SentinelOne"]},
 siem:{label:"SIEM",opts:["Microsoft Sentinel","Splunk","Elastic Security","Sumo Logic"]},
 vuln:{label:"Vulnerability scanner",opts:["Tenable","Qualys","Rapid7 InsightVM"]},
 mdm:{label:"Device management",opts:["Microsoft Intune","Jamf","Kandji"]},
 hris:{label:"HR system",opts:["Workday","BambooHR","Rippling"]},
 vcs:{label:"Code repository",opts:["Azure DevOps","GitHub","GitLab"]},
 lms:{label:"Training platform",opts:["KnowBe4","Proofpoint Security Awareness","Hoxhunt"]},
 docs:{label:"Document repository",opts:["SharePoint","Confluence","Google Drive"]}
};
const CLOUD = {
 azure:{cloudlog:"Azure Monitor activity logs",cloudcfg:"Azure Policy compliance",kms:"Azure Key Vault",backup:"Azure Backup",fw:"Azure NSGs and Azure Firewall",cloudportal:"Microsoft Service Trust Portal"},
 aws:{cloudlog:"AWS CloudTrail",cloudcfg:"AWS Config conformance packs",kms:"AWS KMS",backup:"AWS Backup",fw:"AWS security groups and NACLs",cloudportal:"AWS Artifact"},
 gcp:{cloudlog:"Cloud Audit Logs",cloudcfg:"Security Command Center",kms:"Cloud KMS",backup:"Backup and DR Service",fw:"VPC firewall rules",cloudportal:"Google Compliance Reports Manager"},
 onprem:{cloudlog:"Windows Event Forwarding and syslog",cloudcfg:"Group Policy results",kms:"BitLocker and database TDE settings",backup:"Veeam",fw:"Perimeter firewall",cloudportal:"Colocation provider compliance portal"}
};
const SIZES = {small:"1 to 50 people",mid:"51 to 500 people",large:"500+ people"};
const OWNERS = {
 small:{exec:"CEO",sec:"IT and security lead",it:"IT and security lead",iam:"IT and security lead",hr:"People operations",eng:"Engineering lead",proc:"Operations manager",fac:"Office manager",comp:"Compliance lead"},
 mid:{exec:"CISO",sec:"Security engineering",it:"IT operations",iam:"IT operations",hr:"HR manager",eng:"Engineering manager",proc:"Procurement",fac:"Facilities",comp:"GRC analyst"},
 large:{exec:"Office of the CISO",sec:"Security operations",it:"Infrastructure team",iam:"IAM team",hr:"HR business partner",eng:"Platform engineering",proc:"Third-party risk team",fac:"Corporate security",comp:"GRC team"}
};
const LEAD = {"Document":6,"Record":5,"Screenshot":4,"Config export":4,"System report":4,"Sample set":3,"Log extract":3};
const TYPES = Object.keys(LEAD);
const STATUS = [["not_started","Not started"],["requested","Requested"],["received","Received"],["accepted","Accepted"],["na","Not applicable"]];
const SLABEL = Object.fromEntries(STATUS);
const AUDIT = {
 readiness:{label:"Readiness or internal audit",hint:"Point in time"},
 point:{label:"Point-in-time audit",hint:"ISO stage 2, SOC 2 Type I, C3PAO"},
 period:{label:"Period of operation",hint:"SOC 2 Type II, surveillance, ConMon"}
};
