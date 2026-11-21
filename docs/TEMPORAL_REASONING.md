# Academic Guide: Temporal Knowledge Representation and Reasoning in Cybersecurity

## Abstract
Modern Advanced Persistent Threats (APTs) and multi-stage cyberattacks rarely manifest as single anomalous events on isolated endpoints. Instead, sophisticated adversaries conduct operations across extended time horizons and distributed networks—moving from initial credential access to internal lateral pivoting, privilege escalation, and data staging. Conventional intrusion detection systems (IDS) operating on static thresholding or point-in-time statistical anomalies frequently fail because each individual event often resembles benign activity when observed out of context.

This project implements a formal **Temporal Knowledge Representation and Reasoning Engine** that models security logs as time-dependent facts, extracts temporal predicates, validates Allen's Interval Algebra constraints, and identifies causal candidate relations to detect coordinated cyberattacks with high precision.

---

### 1. Mathematical Formalization of Security Events

Let $E = \{e_1, e_2, \dots, e_n\}$ denote a set of security events occurring across an enterprise network $C = \{c_1, c_2, \dots, c_m\}$. Each event $e_i$ is formalized as a temporal fact tuple:

$$e_i = \langle \text{id}_i, \tau_i, c_i, u_i, s_i, \text{type}_i, a_i, \text{src}_i, \text{dst}_i \rangle$$

Where:
- $\text{id}_i \in \Sigma^*$ is the unique event identifier.
- $\tau_i = [t_i^{\text{start}}, t_i^{\text{end}}]$ represents the temporal interval (for point events, $t_i^{\text{start}} = t_i^{\text{end}} = t_i$).
- $c_i \in C$ is the monitored host/computer.
- $u_i \in U$ is the initiating user identity.
- $s_i \in S$ is the active session identifier.
- $\text{type}_i \in \mathcal{T}$ is the normalized taxonomy classification.
- $a_i$ is the specific operational action.
- $\text{src}_i, \text{dst}_i$ represent the source and destination network endpoints.

---

### 2. Allen's Interval Algebra & Point Relations

Temporal relationships between events are formalized using both point-based orderings and interval algebra:

1. **Strict Precedence ($before$)**:
   $$\text{before}(e_1, e_2) \iff t_1^{\text{end}} < t_2^{\text{start}}$$

2. **Simultaneity ($simultaneous$)**:
   $$\text{simultaneous}(e_1, e_2, \epsilon) \iff |t_1 - t_2| \le \epsilon \quad (\text{default } \epsilon = 2.0\text{s})$$

3. **Time-Bounded Succession ($within\_time\_window$)**:
   $$\text{within\_time\_window}(e_1, e_2, W) \iff 0 \le (t_2 - t_1) \le (W \cdot 60)$$

4. **Interval Overlap ($overlaps$)**:
   $$\text{overlaps}(i_1, i_2) \iff t_1^{\text{start}} < t_2^{\text{end}} \land t_2^{\text{start}} < t_1^{\text{end}}$$

---

### 3. Entity-Binding Predicates

Chronological succession alone ($t_1 < t_2$) is insufficient to infer an attack, as thousands of unrelated users perform actions simultaneously across an enterprise network. To eliminate false positives, temporal predicates are conjoined with **entity-binding constraints**:

1. **User Identity Continuity**:
   $$\text{same\_user}(e_1, e_2) \iff u_1 \neq \emptyset \land u_2 \neq \emptyset \land \text{lower}(u_1) = \text{lower}(u_2)$$

2. **Session Continuity**:
   $$\text{same\_session}(e_1, e_2) \iff s_1 \neq \emptyset \land s_2 \neq \emptyset \land s_1 = s_2$$

3. **Cross-Computer Network Hop**:
   $$\text{related\_computers}(e_1, e_2) \iff (c_1 = c_2) \lor (\text{dst}_1 = \text{src}_2 \land \text{dst}_1 \neq 127.0.0.1)$$

4. **Network Activity Association**:
   $$\text{related\_network}(e_1, e_2) \iff \{\text{src}_1, \text{dst}_1\} \cap \{\text{src}_2, \text{dst}_2\} \setminus \{127.0.0.1, 0.0.0.0\} \neq \emptyset$$

---

### 4. Causal Candidate Inference

A pair of events $(e_1, e_2)$ forms a **Causally Related Candidate** ($e_1 \xrightarrow{\text{causal}} e_2$) if and only if:
1. $\text{before}(e_1, e_2)$ holds.
2. $\text{within\_time\_window}(e_1, e_2, W_{\text{max}})$ holds.
3. At least one entity binding holds ($\text{same\_user} \lor \text{same\_session} \lor \text{related\_computers} \lor \text{related\_network}$).
4. An adversarial transition is semantically plausible in the cyber kill chain (e.g., $E_{\text{fail}} \rightarrow E_{\text{success}}$, $E_{\text{foothold}} \rightarrow E_{\text{lateral}}$, $E_{\text{stage}} \rightarrow E_{\text{exfil}}$).

$$\text{Confidence}(e_1, e_2) = \min\left(1.0, W_{\text{base}} + \sum W_{\text{bindings}} + W_{\text{semantic}}\right)$$

---

### 5. Multi-Stage Coordinated Attack Detection Rule

The multi-stage attack detection rule evaluates a directed temporal path across 5 distinct phases:

$$E_{\text{stage1}} \xrightarrow[\le 15\text{m}]{\text{before}} E_{\text{stage2}} \xrightarrow[\le 30\text{m}]{\text{before}} E_{\text{stage3}} \xrightarrow[\le 30\text{m}]{\text{before}} E_{\text{stage4}} \xrightarrow[\le 30\text{m}]{\text{before}} E_{\text{stage5}}$$

Where:
- $E_{\text{stage1}}$: Repeated authentication failures ($\text{FAILED\_LOGIN}$).
- $E_{\text{stage2}}$: Successful authentication on initial host ($\text{SUCCESSFUL\_LOGIN}$).
- $E_{\text{stage3}}$: Lateral movement to second host ($\text{REMOTE\_LOGIN}$).
- $E_{\text{stage4}}$: Sensitive data access ($\text{SENSITIVE\_FILE\_ACCESS}$).
- $E_{\text{stage5}}$: External data exfiltration ($\text{LARGE\_DATA\_TRANSFER}$).

All events satisfy transitive temporal precedence:

$$\forall i \in \{1, \dots, 4\}, \quad \text{before}(E_{\text{stage}_i}, E_{\text{stage}_{i+1}}) \land \text{within\_time\_window}(E_{\text{stage}_i}, E_{\text{stage}_{i+1}}, W)$$

And cross-machine correlation:

$$c(E_{\text{stage2}}) \neq c(E_{\text{stage3}}) \quad \land \quad (\text{same\_user} \lor \text{src}(E_{\text{stage3}}) = c(E_{\text{stage2}}))$$

This formal temporal approach prevents false alarms caused by isolated events while ensuring coordinated multi-stage campaigns are detected with deterministic certainty.
