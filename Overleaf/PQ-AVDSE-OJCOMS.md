::: keywords
EHRs, dynamic symmetric searchable encryption, bloom filter,
post-quantum, blockchain, foreward privacy, backword privacy.
:::

# Introduction {#sec:introduction}

Internet of Medical Things (IoMT) has fundamentally transformed modern
healthcare by enabling continuous health monitoring through wearable
devices, smart sensors, medical imaging systems, ambulances, and
hospital information systems. Massive volumes of heterogeneous medical
data are continuously generated and shared across hospitals,
laboratories, insurance providers, emergency response centers, and
cloud-edge infrastructures to support real-time diagnosis, telemedicine,
collaborative treatment, and intelligent healthcare analytics. To
accommodate the scalability and computational demands of these
applications, IoMT data are increasingly outsourced to cloud-assisted
platforms. However, outsourcing sensitive medical information to
semi-trusted cloud providers significantly expands the attack surface
and raises critical concerns regarding data confidentiality,
fine-grained authorization, secure search, integrity verification, and
regulatory compliance with healthcare regulations such as HIPAA, GDPR,
and
PDPA [@ref1; @ref2; @ref3; @ref4; @ref5; @ref20; @ref21; @ref47; @ref50; @ref51].

Since encrypted medical data cannot be directly queried, searchable
encryption has become a fundamental technique for secure cloud-based
healthcare systems. Dynamic Searchable Symmetric Encryption (DSSE)
enables encrypted keyword search while supporting dynamic insertions,
deletions, and updates without revealing plaintext
information [@ref29; @ref30; @ref31; @ref37; @ref38; @ref42; @ref45; @ref46].
Recent advances further improve forward and backward privacy, expressive
search capabilities, and multi-user support. To guarantee search
correctness over untrusted cloud servers, Verifiable Dynamic Searchable
Encryption (VDSE) incorporates authenticated data structures, Merkle
proofs, and blockchain-assisted auditing to verify the completeness and
integrity of returned search
results [@ref6; @ref8; @ref9; @ref10; @ref22; @ref23; @ref24; @ref30; @ref31; @ref32; @ref35; @ref46].

The emergence of quantum computing has accelerated research on
quantum-resistant searchable data sharing. Recent studies have explored
Learning With Errors (LWE)-based searchable encryption, lattice-based
cryptographic techniques, and post-quantum secure data-sharing
frameworks to protect outsourced data against future quantum adversaries
while preserving secure search and fine-grained access
control [@ref16; @ref41; @ref52; @ref54; @ref55]. However, these works
primarily focus on quantum-resistant cryptographic primitives, secure
storage, or encrypted query processing, with limited consideration of
dynamic searchable-index maintenance, multi-authority authorization,
verifiable retrieval, and adaptive workload-aware search execution in
distributed fog--cloud IoMT environments.

Meanwhile, multi-authority attribute-based encryption has been
introduced to enable fine-grained authorization across multiple
administrative healthcare organizations [@ref26; @ref27; @ref28]. By
distributing trust among independent authorities, these schemes improve
cross-domain access control and eliminate single points of trust.
However, they generally treat authorization, searchable encryption, and
dynamic index management as independent components, limiting scalability
in continuously evolving IoMT environments.

Despite these advances, existing solutions remain inadequate for
large-scale multi-domain IoMT environments. First, most searchable
encryption schemes assume centralized or static search infrastructures
and cannot efficiently support continuously generated IoMT data across
multiple healthcare domains. Second, current post-quantum and
lattice-based approaches primarily strengthen cryptographic security
without jointly addressing dynamic searchable encryption, verifiable
retrieval, authorization synchronization, and workload-aware search
scheduling. Third, existing multi-authority schemes focus primarily on
attribute-based authorization while treating encrypted search,
authorization management, and dynamic updates as separate processes,
resulting in redundant computation and limited scalability. Fourth,
although verifiable searchable encryption ensures search correctness,
existing approaches incur substantial synchronization overhead as
searchable indexes and authorization states evolve. Finally, current
frameworks rarely optimize encrypted search execution over distributed
fog--cloud infrastructures, leading to unnecessary index traversal,
increased search latency, and inefficient resource utilization under
dynamic IoMT workloads.

To address these limitations, we propose **MA-LB-PQ-VDSE**
(*Multi-Authority Load-Balanced Post-Quantum Verifiable Dynamic
Searchable Encryption*), a secure and scalable framework for large-scale
IoMT data sharing. The proposed framework unifies multi-authority
authorization, dynamic searchable encryption, adaptive search
scheduling, efficient authorization synchronization, blockchain-backed
verifiable retrieval, and post-quantum secure communication within a
single architecture. By tightly coupling authorization management,
encrypted search, dynamic updates, and verification, MA-LB-PQ-VDSE
enables efficient and scalable encrypted retrieval while reducing
synchronization overhead, search latency, and unnecessary index
traversal in continuously evolving multi-domain IoMT environments.

- **Policy-bound multi-authority dynamic searchable encryption.** We
  propose a multi-authority dynamic searchable encryption framework
  based on a *Version-Bound Authorization Profile (VAP)* and a
  *Policy-Bound Dynamic Search Index (PDSI)*. By cryptographically
  binding searchable indexes with authorization policies, authorization
  versions, and authority commitments, the proposed framework enables
  efficient cross-domain encrypted retrieval while reducing unauthorized
  index traversal, metadata leakage, and synchronization overhead.

- **Adaptive authorization-aware search scheduling.** We develop an
  *Adaptive Authorization-Aware Search Scheduler (AASS)* that predicts
  the cryptographic search cost before query execution. Unlike
  conventional resource-centric load-balancing schemes, AASS jointly
  considers authorization consistency, searchable-index locality,
  verification overhead, synchronization cost, and queue latency to
  select the optimal Fog Search Node, thereby improving scalability and
  reducing encrypted-search latency under dynamic IoMT workloads.

- **Incremental authorization synchronization for dynamic searchable
  encryption.** We introduce an *Incremental Authorization
  Synchronization (IAS)* mechanism that jointly updates
  authorization-state commitments, searchable-index entries, Merkle
  roots, and blockchain metadata through localized synchronization. IAS
  supports efficient insertions, modifications, deletions, policy
  evolution, and user revocation without reconstructing the global
  searchable index while preserving authorization consistency and
  publicly verifiable retrieval.

- **Post-quantum verifiable IoMT data sharing.** We integrate
  ML-KEM-based post-quantum key establishment, authenticated encryption,
  and blockchain-anchored Merkle verification into a unified IoMT
  data-sharing framework, providing quantum-resistant key distribution,
  tamper-evident retrieval, authorization-consistent verification, and
  long-term confidentiality for large-scale multi-domain healthcare
  environments.

# Related Work

::: table*
  ----------------------------- -------------- ---------------- --------------- ---------------- ------------------- --------------- ----------------
  **Reference**                  **Dynamic**    **Verifiable**    **Multi-**     **Blockchain**   **Multi-Keyword**     **Load**      **Lattice/PQ**
                                  **Update**      **Search**     **Authority**     **Audit**         **Search**       **Balancing**     **Based**
  LWE-based MWSE [@ref16]          $\times$        $\times$        $\times$         $\times$          $\times$          $\times$       $\checkmark$
  Xu *et al*. [@ref26]             $\times$        $\times$      $\checkmark$       $\times$          $\times$          $\times$         $\times$
  Yu *et al*. [@ref28]           $\checkmark$      $\times$      $\checkmark$     $\checkmark$        $\times$          $\times$         $\times$
  Dou *et al*. [@ref29]          $\checkmark$      $\times$        $\times$         $\times$          $\times$          $\times$         $\times$
  Guo *et al*. [@ref35]          $\checkmark$    $\checkmark$      $\times$         $\times$        $\checkmark$        $\times$         $\times$
  Thingom *et al.* [@ref41]        $\times$        $\times$        $\times$         $\times$          $\times$          $\times$         $\times$
  Chen *et al*. [@ref46]         $\checkmark$    $\checkmark$      $\times$         $\times$          $\times$          $\times$         $\times$
  Gao *et al*. [@ref47]          $\checkmark$      $\times$        $\times$       $\checkmark$      $\checkmark$        $\times$         $\times$
  Perera and Fugkeaw [@ref48]    $\checkmark$      $\times$        $\times$         $\times$        $\checkmark$      $\checkmark$       $\times$
  Deebak and Hwang [@ref51]        $\times$        $\times$        $\times$       $\checkmark$        $\times$          $\times$         $\times$
  Zhuang *et al.* [@ref52]       $\checkmark$      $\times$        $\times$         $\times$          $\times$          $\times$       $\checkmark$
  Chen *et al.* [@ref53]           $\times$        $\times$        $\times$         $\times$          $\times$          $\times$         $\times$
  Perera and Fugkeaw [@ref54]      $\times$      $\checkmark$      $\times$         $\times$          $\times$          $\times$       $\checkmark$
  **Proposed**                   $\checkmark$    $\checkmark$    $\checkmark$     $\checkmark$      $\checkmark$      $\checkmark$     $\checkmark$
  ----------------------------- -------------- ---------------- --------------- ---------------- ------------------- --------------- ----------------
:::

## Blockchain-Assisted Secure Healthcare and IoMT Data Sharing

Blockchain has been widely adopted to provide decentralized trust,
immutable auditing, and fine-grained access control for healthcare and
IoMT data sharing. Malamas *et al.* [@ref1], Gao *et al.* [@ref2], Chen
*et al.* [@ref4], and Yuan *et al.* [@ref5] proposed blockchain-based
architectures for secure medical data sharing and decentralized access
management. Fugkeaw [@ref3] introduced an efficient policy update
mechanism for outsourced health records, while Fugkeaw *et al.* [@ref21]
incorporated adaptive revocation and fog-assisted load sharing for IoT
healthcare systems. More recently, Gao *et al.* [@ref47], Hak and
Fugkeaw [@ref50], and Deebak and Hwang [@ref51] extended
blockchain-assisted healthcare sharing toward cloud-edge IoMT
environments. Although these approaches improve decentralized trust and
access control, they primarily focus on secure storage and
authorization, offering limited support for efficient dynamic searchable
encryption and scalable encrypted retrieval across multiple
administrative domains.

## Dynamic and Verifiable Searchable Encryption

Searchable Symmetric Encryption (SSE) originated with Song *et
al.* [@ref39] and was formally strengthened by Curtmola *et
al.* [@ref40], while Thingom [@ref41] introduced forward-secure
searchable encryption. Recent Dynamic Searchable Symmetric Encryption
(DSSE) schemes have significantly improved dynamic updates,
forward/backward privacy, expressive queries, and multi-user
support [@ref29; @ref33; @ref35; @ref36; @ref37; @ref38; @ref42; @ref45].
To ensure search correctness, numerous verifiable searchable encryption
(VSE) schemes have integrated Merkle authentication, authenticated data
structures, blockchain auditing, and cryptographic
proofs [@ref7; @ref8; @ref9; @ref10; @ref11; @ref12; @ref13; @ref14; @ref22; @ref23; @ref24; @ref25; @ref30; @ref31; @ref32; @ref43; @ref46].
These studies substantially improve security and verifiability; however,
search execution generally remains centralized, verification is largely
decoupled from authorization management, and the schemes do not consider
workload-aware encrypted search in large-scale IoMT environments.

## Multi-Authority Authorization and Searchable Encryption

Fine-grained authorization across multiple organizations has been
extensively studied using Attribute-Based Encryption (ABE). Bethencourt
*et al.* [@ref27] first introduced CP-ABE, which has become the
foundation of secure healthcare data sharing. Xu *et al.* [@ref26]
proposed authorized encrypted search for multi-authority medical
databases, while Yu *et al.* [@ref28] combined blockchain with revocable
multi-authority ABE for Industrial IoT. Other studies explored
certificateless searchable encryption [@ref19], LWE-based multi-writer
searchable encryption [@ref16], multi-user searchable
encryption [@ref17], divertible searchable encryption [@ref18], and
multi-client encrypted search [@ref15]. Despite these advances, existing
multi-authority schemes primarily concentrate on cryptographic
authorization and key management, while overlooking dynamic searchable
encryption over continuously generated IoMT data and intelligent
workload balancing across distributed fog-cloud infrastructures.

Overall, existing research has advanced blockchain-assisted healthcare
sharing, dynamic and verifiable searchable encryption, and
multi-authority authorization independently. However, no existing
framework jointly integrates multi-authority authorization, dynamic
searchable encryption, verifiable encrypted retrieval, blockchain-backed
auditing, and adaptive load-balanced search execution for large-scale
IoMT data sharing. These limitations motivate the proposed framework.

Table [\[tab:comparison\]](#tab:comparison){reference-type="ref"
reference="tab:comparison"} compares representative searchable
encryption frameworks with the proposed scheme. Existing studies have
addressed dynamic searchable encryption, verifiable retrieval,
multi-authority authorization, blockchain-assisted auditing, or
lattice-/post-quantum cryptography individually, but none integrates
these capabilities within a unified framework. Xu *et al*. [@ref26] and
Yu *et al*. [@ref28] support multi-authority access control but lack
verifiable encrypted search and workload-aware search execution.
Representative DSSE and VDSE schemes [@ref29; @ref35; @ref46] improve
dynamic updates, search privacy, and retrieval verification, yet
generally assume centralized search processing and do not provide
blockchain-backed auditing or quantum-resistant security. Recent
lattice-/post-quantum approaches [@ref16; @ref41; @ref52; @ref54]
strengthen cryptographic resilience against quantum adversaries but
primarily focus on secure searchable-encryption constructions rather
than scalable authorization management, verifiable retrieval, and
distributed search orchestration. Blockchain-assisted healthcare
frameworks [@ref47; @ref51] enhance decentralized trust and auditability
but do not jointly support dynamic searchable encryption and verifiable
retrieval, while the load-balanced framework of Perera and
Fugkeaw [@ref48] improves search scalability without supporting
multi-authority authorization, verifiable retrieval, or
quantum-resistant cryptography. In contrast, the proposed framework is
the first to unify dynamic searchable encryption, verifiable retrieval,
multi-authority authorization, blockchain-backed auditing,
lattice-/post-quantum secure communication, expressive Boolean search,
and adaptive authorization-aware load-balanced search execution within a
single architecture for large-scale cross-domain IoMT data sharing.

# Our Proposed System

This section presents the architecture of **MA-LB-PQ-VDSE**, a
multi-authority, load-balanced, post-quantum verifiable dynamic
searchable encryption framework for large-scale IoMT data sharing. The
framework enables fine-grained authorization, dynamic encrypted search,
efficient index maintenance, verifiable retrieval, and adaptive workload
distribution across distributed fog-cloud infrastructures.

## System Model

The overall architecture of the proposed MA-LB-PQ-VDSE framework is
illustrated in Fig. [1](#fig:system){reference-type="ref"
reference="fig:system"}. The framework supports secure, scalable, and
verifiable IoMT data sharing across multiple healthcare organizations by
integrating multi-authority authorization, dynamic searchable
encryption, adaptive load balancing, and blockchain-assisted auditing.
The system consists of the following entities.

<figure id="fig:system" data-latex-placement="!t">
<img src="./MA-LB-PQ-VDSE System Model.png" />
<figcaption>Overall system architecture of the proposed MA-LB-PQ-VDSE
framework.</figcaption>
</figure>

- **IoMT Devices and Gateways:** IoMT devices, including wearable
  sensors, patient monitoring systems, medical equipment, and devices
  deployed in smart ambulances, continuously generate healthcare data.
  Edge gateways aggregate, preprocess, and securely transmit encrypted
  data and metadata to the fog--cloud infrastructure for storage and
  searchable indexing.

- **Data Owner (DO):** The Data Owner, such as a hospital, clinic,
  laboratory, or healthcare provider, encrypts IoMT data, constructs
  dynamic searchable indexes, defines attribute-based access policies,
  digitally signs encrypted records, uploads ciphertexts to IPFS, and
  registers metadata on the consortium blockchain.

- **Data User (DU):** Authorized physicians, specialists, emergency
  responders, researchers, and healthcare personnel issue encrypted
  search queries and decrypt authorized IoMT records. Each user
  possesses attribute-based secret keys issued by one or more Attribute
  Authorities.

- **Multi-Authority (MA):** Multiple independent Attribute Authorities
  manage user attributes within their respective administrative domains,
  such as hospitals, insurance providers, government agencies, and
  medical specialties. Each authority independently performs user
  registration, attribute issuance, revocation, and public parameter
  management while collectively enabling secure cross-domain
  authorization.

- **Authorization Index Manager (AIM):** The Authorization Index Manager
  is an off-chain service that maintains authorization indexes, policy
  mappings, version information, and revocation metadata. Before
  encrypted search is executed, the AIM filters unauthorized ciphertext
  indexes according to the user's effective authorization scope, thereby
  reducing unnecessary search operations and limiting metadata exposure.

- **Load Balancing Controller (LBC):** The Load Balancing Controller
  dynamically distributes encrypted search requests among distributed
  Fog Search Nodes according to workload, resource availability,
  authorization locality, index freshness, and network conditions. This
  component improves scalability, balances resource utilization, and
  mitigates search bottlenecks under bursty IoMT workloads.

- **Fog Search Nodes (FSNs):** Fog Search Nodes are distributed edge
  servers that maintain searchable index shards and execute encrypted
  keyword searches. They perform authorization-aware search, generate
  verifiable search proofs, and return candidate ciphertexts to
  authorized users.

- **InterPlanetary File System (IPFS):** IPFS serves as the
  decentralized storage layer for encrypted IoMT data. Encrypted medical
  records are stored using content identifiers (CIDs), providing
  content-addressable storage, integrity verification, deduplication,
  and efficient distributed data management while keeping large
  encrypted payloads off the blockchain.

- **Consortium Blockchain:** The consortium blockchain functions as the
  trusted audit and coordination layer. Instead of storing encrypted
  IoMT data, it maintains compact metadata, including ciphertext
  commitments, Merkle roots, version-delta commitments, public
  parameters of multiple Attribute Authorities, revocation records, and
  audit logs. This design provides immutable provenance, verifiable
  integrity, rollback resistance, and synchronized authorization states
  with minimal on-chain storage overhead.

# MA-LB-PQ-VDSE Protocol

This section presents the proposed MA-LB-PQ-VDSE protocol for secure and
scalable IoMT data sharing across multiple administrative domains. The
protocol consists of eight phases, including system initialization,
multi-authority registration, user key generation, dynamic
searchable-index construction, secure data outsourcing,
authorization-aware load-balanced search, dynamic update and revocation,
and verifiable retrieval. Table [1](#tab:notation){reference-type="ref"
reference="tab:notation"} summarizes the primary notations used
throughout the protocol.

::: {#tab:notation}
  **Symbol**     **Description**
  -------------- -----------------------------------------
  $AA_i$         $i$th Attribute Authority
  $PK_i,MSK_i$   Public and master secret keys of $AA_i$
  $SK_u$         User attribute secret key
  $M_i$          IoMT data record
  $CT_i$         Encrypted IoMT ciphertext
  $I_i$          Dynamic searchable index
  $CID_i$        IPFS content identifier
  $PID_i$        Access-policy identifier
  $VID_i$        Version identifier
  $ST$           Search token
  $Root_t$       Merkle root at epoch $t$
  $\Pi$          Verification proof
  $AIM$          Authorization Index Manager
  $LBC$          Load Balancing Controller
  $FSN_j$        $j$th Fog Search Node
  $Score_j$      Load-balancing score of $FSN_j$

  : Summary of Major Notations
:::

### **Phase I: System Initialization** {#phase-i-system-initialization .unnumbered}

The system initialization phase establishes the global cryptographic
parameters required for multi-authority attribute-based encryption,
dynamic searchable encryption, post-quantum key establishment,
verifiable retrieval, and blockchain-assisted auditing. A trusted system
initializer first generates the public system parameters, after which
each Attribute Authority independently creates its own cryptographic
credentials for managing domain-specific attributes.

#### Step 1: Global Cryptographic Initialization {#step-1-global-cryptographic-initialization .unnumbered}

The trusted initializer selects bilinear groups $G_1$, $G_2$, and $G_T$
of prime order $p$ with bilinear map $$\begin{equation}
e:G_1\times G_2\rightarrow G_T
\end{equation}$$ and generators $g_1\in G_1$ and $g_2\in G_2$. The
system further initializes the cryptographic primitives
$$\begin{equation}
\mathcal{P}=
\left\{
H,\,
\textsf{SHA-256},\,
\textsf{AES-256-GCM},\,
\textsf{HKDF},\,
\textsf{ML-KEM}
\right\}
\end{equation}$$ where $H$ is used for searchable-index generation,
SHA-256 constructs Merkle commitments, AES-256-GCM encrypts IoMT data,
HKDF derives symmetric session keys, and ML-KEM provides post-quantum
key establishment.

#### Step 2: Multi-Authority Initialization {#step-2-multi-authority-initialization .unnumbered}

Each Attribute Authority $AA_i$ independently executes the setup
algorithm $$\begin{equation}
(MSK_i,PK_i)\leftarrow\textsf{Setup}(1^\lambda)
\end{equation}$$ where the master secret key and public key are
generated as $$\begin{equation}
MSK_i=(\alpha_i,\beta_i)
\end{equation}$$ $$\begin{equation}
PK_i=
\left(
g_1,
g_2,
e(g_1,g_2)^{\alpha_i},
g_1^{\beta_i}
\right)
\end{equation}$$ with
$\alpha_i,\beta_i\overset{\$}{\leftarrow}\mathbb{Z}_p$. Since each
Attribute Authority independently manages a disjoint attribute universe,
no trusted central authority is required after system initialization.

#### Step 3: Public Parameter Publication {#step-3-public-parameter-publication .unnumbered}

The global public parameter set is defined as $$\begin{equation}
\mathcal{PP}=
\left(
G_1,G_2,G_T,e,g_1,g_2,
\{PK_i\}_{i=1}^{N_{AA}},
\mathcal{P}
\right)
\end{equation}$$ where $N_{AA}$ denotes the number of participating
Attribute Authorities. Each authority publishes its public key and
identifier to the consortium blockchain, enabling authenticated
cross-domain authorization and secure attribute verification.

#### Step 4: Infrastructure Initialization {#step-4-infrastructure-initialization .unnumbered}

The cloud--fog infrastructure initializes the Authorization Index
Manager (AIM), the Load Balancing Controller (LBC), and the Fog Search
Node set $$\begin{equation}
\mathcal{F}=
\{FSN_1,FSN_2,\ldots,FSN_m\}
\end{equation}$$ where each Fog Search Node maintains searchable-index
shards and executes encrypted search requests. Simultaneously, the
consortium blockchain initializes the system metadata repository for
storing authority public parameters, Merkle roots, version identifiers,
revocation information, and audit logs, thereby providing immutable
integrity protection and synchronized authorization states throughout
the system.

### **Phase II: Multi-Authority Registration and Authorization-State Commitment** {#phase-ii-multi-authority-registration-and-authorization-state-commitment .unnumbered}

Following system initialization, each Attribute Authority (AA) joins the
federated IoMT environment by registering its public credentials,
initializing its attribute namespace, and generating a cryptographic
commitment representing its current authorization state. Unlike
conventional multi-authority systems that maintain only public
parameters, the proposed framework binds the authority identity, managed
attributes, authorization version, and revocation state into a
blockchain-anchored commitment. This commitment serves as the root of
trust for subsequent attribute issuance, authorization verification,
dynamic updates, and revocation synchronization.

#### Step 1: Authority Registration {#step-1-authority-registration .unnumbered}

Each Attribute Authority $AA_i$ registers its identity by publishing
$$\begin{equation}
Reg_i=
(ID_i,Dom_i,PK_i)
\end{equation}$$ where $ID_i$ denotes the authority identifier, $Dom_i$
represents the administrative domain (e.g., hospital, laboratory,
insurance provider, or emergency service), and $PK_i$ is the authority
public key generated during Phase I. The registration record is
permanently anchored on the consortium blockchain, allowing all
participating domains to authenticate the authority before accepting its
issued attributes.

#### Step 2: Attribute Namespace Initialization {#step-2-attribute-namespace-initialization .unnumbered}

Each authority independently initializes its managed attribute universe
$$\begin{equation}
\mathcal{A}_i=
\{a_{i,1},a_{i,2},\ldots,a_{i,n_i}\}
\end{equation}$$ where every attribute belongs exclusively to one
authority. This decentralized namespace eliminates attribute conflicts
across administrative domains while enabling independent attribute
management and policy evolution.

#### Step 3: Authorization-State Commitment {#step-3-authorization-state-commitment .unnumbered}

Each authority initializes its authorization state by assigning a
version identifier $VID_i$ and constructing an authenticated revocation
root $RevRoot_i$ over the current revocation list. The authority then
computes a compact authorization-state commitment $$\begin{equation}
C_i^{auth}
=
H\!\left(
ID_i
\parallel
Dom_i
\parallel
H(\mathcal{A}_i)
\parallel
VID_i
\parallel
RevRoot_i
\right)
\end{equation}$$ where $H(\mathcal{A}_i)$ denotes the digest of the
authority's attribute namespace. The commitment uniquely binds the
authority identity, managed attributes, authorization version, and
revocation state into a single cryptographic fingerprint.

#### Step 4: Blockchain Commitment and Synchronization {#step-4-blockchain-commitment-and-synchronization .unnumbered}

The authority publishes $$\begin{equation}
State_i=
(ID_i,PK_i,C_i^{auth},VID_i)
\end{equation}$$ to the consortium blockchain. Simultaneously, the
Authorization Index Manager (AIM) synchronizes the latest authorization
metadata $$\begin{equation}
Meta_i=
(Dom_i,VID_i,C_i^{auth})
\end{equation}$$ across all cloud--fog search infrastructures. During
subsequent attribute updates or user revocations, only the affected
authority recomputes its authorization-state commitment and publishes a
new version identifier, enabling localized authorization synchronization
without requiring global policy reconstruction or system-wide
reinitialization.

### **Phase III: User Registration and Version-Bound Authorization Profile Generation** {#phase-iii-user-registration-and-version-bound-authorization-profile-generation .unnumbered}

Following authority registration, each Data Owner (DO) and Data User
(DU) enrolls with one or more Attribute Authorities according to their
organizational roles and operational responsibilities. During
enrollment, participating authorities collaboratively issue
attribute-based secret keys while the Authorization Index Manager (AIM)
constructs a version-bound authorization profile that securely binds the
user's identity, attributes, authorization state, and participating
authorities into a compact cryptographic commitment. This profile serves
as the authorization anchor for subsequent encrypted search, dynamic
updates, revocation, and verifiable retrieval.

#### Step 1: User Registration {#step-1-user-registration .unnumbered}

A user $U$ submits $$\begin{equation}
Req_U=
(UID,Dom,Role,Cred)
\end{equation}$$ where $UID$ denotes the user identity, $Dom$ is the
administrative domain, $Role$ specifies the organizational role, and
$Cred$ contains the supporting credentials required for attribute
verification. Each participating Attribute Authority independently
validates the submitted credentials according to its local policy.

#### Step 2: Multi-Authority Attribute Key Generation {#step-2-multi-authority-attribute-key-generation .unnumbered}

Suppose user $U$ is assigned the attribute subset $$\mathcal{S}_{U,i}
\subseteq
\mathcal{A}_i$$ by Attribute Authority $AA_i$. The authority generates
the corresponding attribute secret key component $$\begin{equation}
SK_{U,i}
\leftarrow
\textsf{KeyGen}(MSK_i,\mathcal{S}_{U,i})
\end{equation}$$

If the user receives attributes from multiple authorities, the complete
authorization key becomes $$\begin{equation}
SK_U
=
\bigcup_{i=1}^{N_U}
SK_{U,i}
\end{equation}$$ where $N_U$ denotes the number of participating
Attribute Authorities.

#### Step 3: Post-Quantum Secure Key Delivery {#step-3-post-quantum-secure-key-delivery .unnumbered}

To securely distribute attribute keys, each Attribute Authority
establishes a post-quantum shared secret using ML-KEM $$\begin{equation}
(ct_i,ss_i)
\leftarrow
\textsf{ML\mbox{-}KEM.Encaps}(pk_U^{KEM})
\end{equation}$$ where $pk_U^{KEM}$ is the user's public key. The shared
secret is expanded by HKDF, $$\begin{equation}
K_i=
\textsf{HKDF}(ss_i)
\end{equation}$$ and used to encrypt the attribute secret key
$$\begin{equation}
EncKey_i
=
\textsf{AES\mbox{-}256\mbox{-}GCM.Enc}
(K_i,SK_{U,i})
\end{equation}$$

This mechanism provides confidentiality, forward secrecy, and resistance
against quantum adversaries during attribute-key distribution.

#### Step 4: Version-Bound Authorization Profile Generation {#step-4-version-bound-authorization-profile-generation .unnumbered}

After successful key delivery, the Authorization Index Manager (AIM)
aggregates the authorization information associated with user $U$. Let
$$\mathcal{S}_U
=
\bigcup_{i=1}^{N_U}
\mathcal{S}_{U,i}$$ denote the complete attribute set, and let
$$\mathcal{C}_U
=
\{
C_1^{auth},
C_2^{auth},
\ldots,
C_{N_U}^{auth}
\}$$ be the collection of authorization-state commitments published by
the participating Attribute Authorities.

The AIM assigns the current authorization version identifier $VID_U$ and
computes the user's version-bound authorization root $$\begin{equation}
AuthRoot_U=
H
\left(
UID
\parallel
H(\mathcal{S}_U)
\parallel
VID_U
\parallel
H(\mathcal{C}_U)
\right)
\end{equation}$$ which uniquely binds the user identity, authorized
attributes, authorization version, and authority commitments into a
single cryptographic fingerprint.

The resulting Version-Bound Authorization Profile is $$\begin{equation}
VAP_U=
(
UID,
\mathcal{D}_U,
AuthRoot_U,
VID_U,
\mathcal{C}_U
)
\end{equation}$$ where $\mathcal{D}_U$ denotes the set of authorized
administrative domains.

The VAP is maintained by the Authorization Index Manager and
periodically synchronized with the consortium blockchain. During
subsequent attribute modifications or user revocations, only the
affected authority commitment and authorization version are updated,
allowing localized authorization synchronization without rebuilding
global authorization metadata. The generated $AuthRoot_U$ is
subsequently incorporated into search-token generation, authorization
verification, and verifiable retrieval, thereby providing consistent
authorization semantics throughout the proposed framework.

### **Phase IV: Policy-Bound Dynamic Search Index Construction** {#phase-iv-policy-bound-dynamic-search-index-construction .unnumbered}

Following user registration, each DO encrypts IoMT data and constructs a
dynamic searchable index that is cryptographically bound to both the
access policy and the current multi-authority authorization state.
Unlike conventional searchable encryption schemes that maintain keyword
indexes independently of authorization, the proposed framework embeds
policy identifiers, authorization versions, and integrity commitments
directly into each searchable index. Consequently, encrypted search,
authorization verification, dynamic updates, and result verification
operate over a unified index structure while avoiding global index
reconstruction.

#### Step 1: Keyword and Metadata Extraction {#step-1-keyword-and-metadata-extraction .unnumbered}

For each IoMT record $$M_i$$ the Data Owner extracts $$W_i=
\{
w_1,\ldots,w_t
\}$$ together with associated metadata $$Meta_i=
(
PID_i,
VID_i,
Dom_i,
TS_i
)$$ where $PID_i$ denotes the access-policy identifier, $VID_i$ denotes
the authorization version, $Dom_i$ denotes the authority domain, $TS_i$
denotes the timestamp.

#### Step 2: Policy-Bound Keyword Encoding {#step-2-policy-bound-keyword-encoding .unnumbered}

For every keyword $$w_j
\in
W_i$$ the Data Owner computes $$\begin{equation}
T_j
=
H
(
w_j
\parallel
PID_i
\parallel
VID_i
\parallel
Dom_i
)
\end{equation}$$

The resulting keyword token is uniquely bound to the current
authorization policy and authorization version, thereby preventing token
reuse across policy updates and limiting cross-domain linkage.

#### Step 3: Dynamic Search Index Construction {#step-3-dynamic-search-index-construction .unnumbered}

Each encoded keyword generates an index entry $$\begin{equation}
I_j=
(
T_j,
CID_i,
PID_i,
VID_i
)
\end{equation}$$ where $$CID_i$$ is the IPFS content identifier.

All index entries are inserted into the Dynamic Search Index $$DSI
=
\bigcup
I_j$$

Unlike conventional inverted indexes, each index entry remains
independently updateable, allowing insertions, deletions, and policy
modifications without rebuilding the entire searchable index.

#### Step 4: Batch Integrity Commitment {#step-4-batch-integrity-commitment .unnumbered}

To minimize verification overhead, the Data Owner batches all index
entries associated with one IoMT record into a Merkle tree.

The leaf node corresponding to index entry $I_j$ is $$L_j
=
H(I_j)$$ and the Merkle root is $$Root_i
=
MerkleRoot
(
\{
L_j
\}
)$$

Only the Merkle root is committed to the blockchain, while the
authentication paths are maintained by the cloud infrastructure for
subsequent verifiable retrieval.

#### Step 5: Policy Commitment Generation {#step-5-policy-commitment-generation .unnumbered}

Finally, the Data Owner computes $$\begin{equation}
Commit_i
=
H
(
Root_i
\parallel
PID_i
\parallel
VID_i
\parallel
AuthRoot_{DO}
)
\end{equation}$$

The commitment binds the encrypted IoMT data, searchable index,
authorization policy, authorization version, and the Data Owner's
authorization profile into a single immutable digest.

### **Phase V: Secure Data Outsourcing** {#phase-v-secure-data-outsourcing .unnumbered}

Following dynamic index construction, the Data Owner securely outsources
the encrypted IoMT data, searchable indexes, and integrity commitments
to the cloud--fog infrastructure. To minimize blockchain storage
overhead, only compact cryptographic commitments and metadata are
recorded on-chain, while encrypted data and searchable indexes remain
off-chain. This separation provides scalable storage, efficient search,
and publicly verifiable integrity.

#### Step 1: Encrypted Data Outsourcing {#step-1-encrypted-data-outsourcing .unnumbered}

The encrypted IoMT ciphertext $$CT_i
=
\left(
C_i,
I_i,
Commit_i
\right)$$ where $C_i$ is the encrypted IoMT record, $I_i$ denotes the
Policy-Bound Dynamic Search Index, and $Commit_i$ is the policy
commitment generated in Phase IV, is uploaded to the decentralized IPFS
storage network.

Upon successful storage, IPFS returns a unique content identifier
$$CID_i
=
\textsf{IPFS.Upload}(CT_i)$$ which serves as the immutable reference for
subsequent retrieval.

#### Step 2: Metadata Registration {#step-2-metadata-registration .unnumbered}

Instead of recording encrypted data on-chain, the Data Owner registers
only compact searchable metadata $$\begin{equation}
Meta_i=
(
CID_i,
PID_i,
VID_i,
Root_i,
Commit_i
)
\end{equation}$$ where $PID_i$ is the policy identifier, $VID_i$ denotes
the authorization version, $Root_i$ is the Merkle root of the searchable
index, and $Commit_i$ is the policy commitment.

The metadata are maintained by the cloud--fog infrastructure and
synchronized with the consortium blockchain.

#### Step 3: Blockchain Commitment {#step-3-blockchain-commitment .unnumbered}

The consortium blockchain stores the immutable transaction
$$\begin{equation}
BC_i=
(
CID_i,
Commit_i,
Root_i,
VID_i,
TS_i
)
\end{equation}$$ where $TS_i$ denotes the transaction timestamp.

Since only compact metadata are recorded, the blockchain storage
complexity remains independent of the encrypted IoMT data size.

#### Step 4: Search Infrastructure Synchronization {#step-4-search-infrastructure-synchronization .unnumbered}

After successful blockchain confirmation, the cloud--fog infrastructure
synchronizes the searchable index and associated metadata with the
Authorization Index Manager (AIM) and the distributed Fog Search Nodes
(FSNs). Specifically, $$\begin{equation}
Sync_i=
(
I_i,
PID_i,
VID_i,
CID_i
)
\end{equation}$$ is propagated to the authorized Fog Search Nodes.

Rather than replicating encrypted IoMT data, each Fog Search Node
maintains only searchable-index shards and corresponding metadata
required for encrypted search. Consequently, encrypted data remain
stored exclusively in IPFS, while distributed search execution can be
performed with low synchronization overhead.

#### Step 5: Index Availability {#step-5-index-availability .unnumbered}

Finally, the Authorization Index Manager updates the searchable index
catalog $$\begin{equation}
Catalog
\leftarrow
Catalog
\cup
(CID_i,PID_i,VID_i)
\end{equation}$$ allowing subsequent search requests to efficiently
locate authorized searchable-index shards without scanning the complete
encrypted repository.

### **Phase VI: Adaptive Authorization-Aware Search Scheduling** {#phase-vi-adaptive-authorization-aware-search-scheduling .unnumbered}

Upon receiving an encrypted search request, the proposed framework first
validates the user's authorization state and then predicts the
cryptographic search cost of executing the query at each Fog Search Node
(FSN). Unlike conventional searchable encryption schemes that forward
queries to a predefined server or balance requests solely according to
processor utilization, the proposed framework jointly optimizes
authorization consistency, searchable-index locality, verification
overhead, and queue delay before encrypted search is performed.
Consequently, search execution is restricted to authorized index shards
while minimizing the overall cryptographic processing cost.

#### Step 1: Search Token Generation {#step-1-search-token-generation .unnumbered}

Suppose the Data User intends to search the keyword set
$$Q=\{w_1,w_2,\ldots,w_q\}$$

Using the Version-Bound Authorization Profile
$$VAP_U=(UID,\mathcal{D}_U,AuthRoot_U,VID_U,\mathcal{C}_U)$$

the Data User generates the search token $$\begin{equation}
ST=
\left(
T_Q,
AuthRoot_U,
VID_U,
\rho
\right)
\end{equation}$$ where $$\begin{equation}
T_Q=
\left\{
H(w_i\parallel VID_U)
\right\}_{i=1}^{q}
\end{equation}$$ and $\rho$ is a fresh random nonce preventing replay
attacks. The search token is transmitted to the Authorization Index
Manager (AIM).

#### Step 2: Authorization Verification {#step-2-authorization-verification .unnumbered}

The Authorization Index Manager verifies the submitted authorization
state by checking the user's authorization root, authorization version,
participating authority commitments, and permitted administrative
domains. If $$(AuthRoot_U,VID_U,\mathcal{C}_U)$$ are consistent with the
latest authorization state maintained by the participating Attribute
Authorities, the AIM identifies the authorized searchable-index shards
and forwards the validated search request to the Adaptive
Authorization-Aware Search Scheduler (AASS). Otherwise, the request is
rejected without traversing the encrypted index.

#### Step 3: Adaptive Authorization-Aware Search Scheduling {#step-3-adaptive-authorization-aware-search-scheduling .unnumbered}

Let $$\mathcal{F}=
\{FSN_1,FSN_2,\ldots,FSN_m\}$$ denote the available Fog Search Nodes.

For each node $FSN_j$, the scheduler predicts the total encrypted-search
cost $$\begin{equation}
SC_j=
\lambda_1C_j^{auth}
+\lambda_2C_j^{index}
+\lambda_3C_j^{verify}
+\lambda_4C_j^{sync}
+\lambda_5C_j^{queue}
\end{equation}$$ where

- $C_j^{auth}$ denotes the authorization evaluation cost

- $C_j^{index}$ denotes the searchable-index traversal cost

- $C_j^{verify}$ denotes the Merkle-proof generation cost

- $C_j^{sync}$ denotes the authorization-version synchronization cost

- $C_j^{queue}$ denotes the expected queue waiting time

The individual costs are estimated as $$\begin{align}
C_j^{auth} &= |\mathcal{P}_Q|\\
C_j^{index} &= |\widehat{Cand}_Q^{(j)}|\\
C_j^{verify} &= |\widehat{R}_Q^{(j)}|\log N_j\\
C_j^{sync} &= |VID_U-VID_j|\\
C_j^{queue} &= T_j^{queue}
\end{align}$$ where

- $|\mathcal{P}_Q|$ is the number of authorization policies involved in
  the query

- $|\widehat{Cand}_Q^{(j)}|$ is the estimated candidate set size
  maintained by the local searchable-index statistics

- $|\widehat{R}_Q^{(j)}|$ is the predicted number of matching
  ciphertexts;

- $N_j$ is the number of searchable-index entries maintained by $FSN_j$

- $VID_j$ is the latest authorization version synchronized at $FSN_j$

- $T_j^{queue}$ is the current waiting time of the search queue

The scheduler selects $$\begin{equation}
FSN^{*}
=
\arg\min_{FSN_j\in\mathcal{F}}
SC_j
\end{equation}$$

Algorithm [\[alg:aass\]](#alg:aass){reference-type="ref"
reference="alg:aass"} summarizes the proposed AASS procedure, which
selects the Fog Search Node with the minimum predicted cryptographic
search cost rather than merely choosing the least-loaded node.

:::: algorithm
::: algorithmic
Search token $ST$, authorized shard set $\mathcal{S}_Q$, candidate Fog
Search Nodes $\mathcal{F}$

Selected Fog Search Node $FSN^*$

$SC_{\min}\gets\infty$

**continue**

$SC_j\gets
    EstimateSearchCost(FSN_j,ST,\mathcal{S}_Q)$

$SC_{\min}\gets SC_j$ $FSN^*\gets FSN_j$

Dispatch $(ST,\mathcal{S}_Q)$ to $FSN^*$

$FSN^*$
:::
::::

Unlike conventional load balancing algorithms that rely solely on
processor utilization or memory consumption, AASS predicts the expected
cryptographic workload before executing encrypted search, thereby
reducing unnecessary authorization synchronization, searchable-index
traversal, and proof-generation overhead.

#### Step 4: Distributed Encrypted Search {#step-4-distributed-encrypted-search .unnumbered}

The selected Fog Search Node performs encrypted search only over the
authorized searchable-index shards. For every search token, matching
entries are retrieved from the Policy-Bound Dynamic Search Index
$$\begin{equation}
R=
\{
(CID_i,PID_i,VID_i)
\mid
T_Q\rightarrow I_i
\}
\end{equation}$$ where $CID_i$ denotes the encrypted IoMT record stored
in IPFS, $PID_i$ is the associated policy identifier, and $VID_i$ is the
authorization version. Since only authorized index shards are searched,
unnecessary encrypted-search operations over unrelated domains are
avoided.

#### Step 5: Verifiable Search Response Generation {#step-5-verifiable-search-response-generation .unnumbered}

For every matching ciphertext, the selected Fog Search Node generates
the verification bundle $$\begin{equation}
\Pi_i=
(
CID_i,
Root_i,
Commit_i,
\pi_i
)
\end{equation}$$ where $Root_i$ is the Merkle root of the corresponding
searchable index, $Commit_i$ is the policy commitment generated in
Phase IV, and $\pi_i$ is the Merkle authentication path.

The search response returned to the DU is $$\begin{equation}
Resp=
\left\{
(CID_i,\Pi_i)
\right\}_{i=1}^{|R|}
\end{equation}$$ which will be verified in Phase VIII prior to
retrieving the encrypted IoMT data from IPFS.

### **Phase VII: Dynamic Index Evolution and Incremental Authorization Synchronization** {#phase-vii-dynamic-index-evolution-and-incremental-authorization-synchronization .unnumbered}

Large-scale IoMT environments require continuous support for data
insertion, modification, deletion, policy updates, and user revocation.
Rebuilding the entire searchable index or synchronizing all Fog Search
Nodes (FSNs) after each update is inefficient. Therefore, MA-LB-PQ-VDSE
introduces an *Incremental Authorization Synchronization* (IAS)
mechanism that updates only the affected authorization state,
searchable-index entries, Merkle commitments, and blockchain metadata.

#### Step 1: Dynamic Update Request {#step-1-dynamic-update-request .unnumbered}

For an affected IoMT record $M_i$, the Data Owner issues an update
request $$\begin{equation}
U_i=(Op,CID_i,\Delta_i)
\end{equation}$$ where
$$Op\in\{\mathsf{Insert},\mathsf{Modify},\mathsf{Delete},\mathsf{Revoke}\}$$
$CID_i$ denotes the IPFS content identifier, and $\Delta_i$ contains the
affected keywords, policy changes, metadata changes, or revocation
information.

#### Step 2: Localized Searchable-Index Evolution {#step-2-localized-searchable-index-evolution .unnumbered}

Only the affected searchable-index entries are updated. For each
modified keyword or policy binding, the Data Owner computes the updated
policy-bound token $$\begin{equation}
T_j'
=
H(w_j\parallel PID_i'\parallel VID_i'\parallel Dom_i)
\end{equation}$$ and generates the updated index entry
$$\begin{equation}
I_j'
=
(T_j',CID_i,PID_i',VID_i')
\end{equation}$$

The index delta is defined as $$\begin{equation}
\Delta I_i=
\{I_j'\}_{j\in \mathcal{W}_\Delta}
\end{equation}$$ where $\mathcal{W}_\Delta$ denotes the set of affected
keywords. Unchanged index entries are not rebuilt.

#### Step 3: Authorization-State Evolution {#step-3-authorization-state-evolution .unnumbered}

If the update affects access policies, user attributes, or revocation
state, the responsible Attribute Authority $AA_k$ increments its
authorization version $$\begin{equation}
VID_k' = VID_k + 1
\end{equation}$$ updates its revocation root $RevRoot_k'$, and
recomputes the authorization-state commitment $$\begin{equation}
C_k^{auth'}
=
H\!\left(
ID_k
\parallel
Dom_k
\parallel
H(\mathcal{A}_k)
\parallel
VID_k'
\parallel
RevRoot_k'
\right)
\end{equation}$$

Only the affected authority updates its commitment, while all other
authorities retain their existing authorization states.

#### Step 4: Incremental Merkle Commitment Update {#step-4-incremental-merkle-commitment-update .unnumbered}

Let $\mathcal{L}_\Delta$ be the set of modified Merkle leaves
corresponding to $\Delta I_i$. Instead of reconstructing the entire
Merkle tree, the cloud--fog infrastructure recomputes only the affected
authentication paths: $$\begin{equation}
Root_i'
=
\textsf{MerkleUpdate}(Root_i,\mathcal{L}_\Delta)
\end{equation}$$

The updated policy commitment is then computed as $$\begin{equation}
Commit_i'
=
H(Root_i'\parallel PID_i'\parallel VID_i'\parallel AuthRoot_{DO})
\end{equation}$$

#### Step 5: IAS Message Generation {#step-5-ias-message-generation .unnumbered}

The AIM constructs an Incremental Authorization Synchronization message
$$\begin{equation}
IAS_i=
(
CID_i,
\Delta VID_i,
\Delta C_i^{auth},
\Delta I_i,
\Delta Root_i,
Commit_i'
)
\end{equation}$$ where $\Delta VID_i=VID_i'-VID_i$, $\Delta C_i^{auth}$
denotes the updated authority commitment, $\Delta I_i$ contains only the
modified searchable-index entries, and $\Delta Root_i=Root_i'-Root_i$
denotes the updated integrity commitment.

#### Step 6: Selective Synchronization to FSNs {#step-6-selective-synchronization-to-fsns .unnumbered}

Rather than broadcasting the complete index state, the AIM forwards
$IAS_i$ only to FSNs that maintain the affected searchable-index shards.
Each receiving FSN updates its local shard state as $$\begin{equation}
Shard_j'
=
\textsf{ApplyIAS}(Shard_j,IAS_i)
\end{equation}$$

FSNs that have not yet applied the latest IAS message are assigned a
higher version-synchronization cost in Phase VI. Therefore, the AASS
scheduler naturally prefers fresh FSNs and avoids stale authorization
states during encrypted search.

#### Step 7: Blockchain Anchoring {#step-7-blockchain-anchoring .unnumbered}

Finally, the consortium blockchain stores the compact update commitment
$$\begin{equation}
BC_i'
=
(CID_i,Commit_i',Root_i',VID_i',TS_i')
\end{equation}$$ where $TS_i'$ is the update timestamp. This creates a
tamper-evident history of dynamic index evolution and
authorization-state changes while avoiding global index reconstruction
and excessive on-chain storage.

### **Phase VIII: Verifiable Retrieval and Secure Decryption** {#phase-viii-verifiable-retrieval-and-secure-decryption .unnumbered}

Upon receiving the search response from the selected Fog Search Node,
the Data User verifies the authenticity, integrity, and authorization
consistency of every returned ciphertext before retrieving the encrypted
IoMT data from IPFS. Unlike conventional verifiable searchable
encryption schemes that verify only the returned search results, the
proposed framework jointly validates the authorization state,
searchable-index integrity, policy commitment, and blockchain
commitment, thereby ensuring that the retrieved data are both
cryptographically correct and authorized under the latest system state.

#### Step 1: Verification Bundle Validation {#step-1-verification-bundle-validation .unnumbered}

For every returned result $$Resp=
\{
(CID_i,\Pi_i)
\}_{i=1}^{|R|}$$ the Data User extracts $$\Pi_i=
(CID_i,Root_i,Commit_i,\pi_i)$$ where $Root_i$ is the Merkle root,
$Commit_i$ is the policy commitment, and $\pi_i$ denotes the Merkle
authentication path.

The user first verifies the Merkle proof by evaluating
$$\begin{equation}
\textsf{VerifyMerkle}
(Root_i,\pi_i,CID_i)=1
\end{equation}$$

If the verification fails, the corresponding ciphertext is immediately
rejected.

#### Step 2: Authorization-State Verification {#step-2-authorization-state-verification .unnumbered}

The Data User subsequently validates that the returned ciphertext
remains consistent with the current authorization state.

Using the latest Version-Bound Authorization Profile $$VAP_U=
(UID,\mathcal D_U,AuthRoot_U,VID_U,\mathcal C_U)$$ the user verifies
$$\begin{equation}
VID_i = VID_U
\end{equation}$$ and recomputes $$\begin{equation}
Commit_i^{*}
=
H
(
Root_i
\parallel
PID_i
\parallel
VID_i
\parallel
AuthRoot_U
)
\end{equation}$$

The ciphertext is accepted only if $$\begin{equation}
Commit_i^{*}=Commit_i
\end{equation}$$

This verification guarantees that the search result was generated under
the latest authorization version and has not been affected by stale
authorization states or outdated policy information.

#### Step 3: Blockchain Consistency Verification {#step-3-blockchain-consistency-verification .unnumbered}

The user retrieves the corresponding blockchain metadata $$BC_i=
(CID_i,Commit_i,Root_i,VID_i,TS_i)$$ and verifies that the locally
computed values match the immutable blockchain commitment. This step
ensures that neither the searchable index nor the integrity commitment
has been modified after publication.

#### Step 4: Secure Ciphertext Retrieval {#step-4-secure-ciphertext-retrieval .unnumbered}

After successful verification, the encrypted IoMT record is retrieved
from IPFS using $$\begin{equation}
CT_i
=
\textsf{IPFS.Get}(CID_i)
\end{equation}$$

Since the blockchain stores only metadata and integrity commitments, the
retrieval process incurs constant on-chain communication overhead
irrespective of the ciphertext size.

#### Step 5: Multi-Authority Decryption {#step-5-multi-authority-decryption .unnumbered}

The encrypted session key is first recovered using the user's attribute
secret key $$\begin{equation}
K_i
=
\textsf{Decrypt}
(SK_U,CT_{K_i})
\end{equation}$$ provided that the user's attribute set satisfies the
embedded access policy.

The original IoMT record is then recovered using authenticated
decryption $$\begin{equation}
M_i
=
\textsf{AES\mbox{-}256\mbox{-}GCM.Dec}
(K_i,C_i)
\end{equation}$$ where $C_i$ denotes the encrypted payload.

If either the authorization policy is not satisfied or the ciphertext
authentication fails, the decryption process terminates without
revealing any information.

#### Step 6: Retrieval Audit Logging {#step-6-retrieval-audit-logging .unnumbered}

Finally, the retrieval event is recorded as $$\begin{equation}
Audit_i=
(
UID,
CID_i,
VID_i,
TS_i,
Result
)
\end{equation}$$ where $Result\in\{\textsf{Success},\textsf{Reject}\}$
indicates the verification outcome. The audit log is anchored on the
consortium blockchain, providing immutable evidence of every successful
and unsuccessful retrieval while supporting regulatory compliance and
post-incident forensic analysis.

# Security Analysis {#sec:security}

This section analyzes the security of the proposed MA-LB-PQ-VDSE
framework under the threat model described in
Section [\[sec:threat\]](#sec:threat){reference-type="ref"
reference="sec:threat"}. We consider probabilistic polynomial-time (PPT)
adversaries, including quantum polynomial-time (QPT) adversaries,
capable of observing, modifying, and replaying network messages while
interacting with the cloud--fog infrastructure. The analysis focuses on
the confidentiality of outsourced IoMT data, privacy of search tokens,
correctness of authorization-aware encrypted search, integrity of
dynamic updates, verifiable retrieval, and post-quantum security.

## Security Model and Assumptions

Let $\lambda$ denote the security parameter. The proposed framework
consists of multiple Attribute Authorities (AAs), Data Owners (DOs),
Data Users (DUs), Fog Search Nodes (FSNs), the Authorization Index
Manager (AIM), IPFS, and a consortium blockchain.

The Attribute Authorities, Data Owners, and legitimate Data Users are
assumed to follow the protocol honestly. The cloud infrastructure,
including the Fog Search Nodes, Authorization Index Manager, and IPFS
storage, is assumed to be *honest-but-curious*; these entities
faithfully execute the protocol but may attempt to infer sensitive
information from encrypted data, searchable indexes, search tokens,
authorization metadata, or dynamic update messages. The consortium
blockchain is assumed to provide immutable storage and authenticated
consensus.

We consider the following adversaries.

- **Cloud Adversary ($\mathcal{A}_C$).** Controls the cloud
  infrastructure, including the Authorization Index Manager, IPFS, and
  Fog Search Nodes. The adversary observes encrypted IoMT data,
  searchable indexes, search tokens, authorization metadata, and update
  messages but does not possess valid attribute secret keys.

- **Malicious Fog Adversary ($\mathcal{A}_F$).** Controls one or more
  Fog Search Nodes and attempts to return incomplete search results,
  stale searchable-index versions, forged verification proofs, or
  replayed authorization states.

- **Revoked User Adversary ($\mathcal{A}_R$).** Represents a previously
  authorized user attempting to reuse revoked attribute keys, replay
  outdated search tokens, or access newly inserted IoMT records after
  revocation.

- **External Adversary ($\mathcal{A}_E$).** Can eavesdrop, replay,
  modify, or inject protocol messages over public communication channels
  but cannot compromise trusted authorities or break the underlying
  cryptographic primitives.

- **Quantum Adversary ($\mathcal{A}_Q$).** Represents a quantum
  polynomial-time adversary capable of executing quantum algorithms
  against classical public-key cryptography while remaining
  computationally bounded with respect to the security assumptions of
  ML-KEM and the collision resistance of the employed hash function.

The security of MA-LB-PQ-VDSE relies on the following standard
cryptographic assumptions.

**Assumption 1 (Collision-Resistant Hash Function).** The cryptographic
hash function $$H:\{0,1\}^{*}\rightarrow\{0,1\}^{\lambda}$$ is collision
resistant, preimage resistant, and behaves as a random oracle.

**Assumption 2 (Multi-Authority ABE Security).** The underlying
multi-authority ciphertext-policy attribute-based encryption scheme is
selectively IND-CPA secure against probabilistic polynomial-time
adversaries.

**Assumption 3 (Authenticated Encryption).** AES-256-GCM provides
IND-CPA confidentiality and ciphertext integrity under authenticated
encryption.

**Assumption 4 (Post-Quantum Key Encapsulation).** ML-KEM is IND-CCA
secure against quantum polynomial-time adversaries.

**Assumption 5 (Merkle Tree Integrity).** Given the collision resistance
of $H$, no probabilistic polynomial-time adversary can construct a valid
Merkle authentication path for an unauthorized or modified leaf without
finding a hash collision.

**Assumption 6 (Blockchain Integrity).** The consortium blockchain
guarantees append-only storage, authenticated consensus, and
immutability of committed metadata once a block is finalized.

## Leakage Model

As with practical dynamic searchable encryption schemes, MA-LB-PQ-VDSE
does not completely hide access patterns or result sizes. The adversary
is assumed to learn only the following leakage function $$\mathcal{L}
=
(
\mathcal{L}_{setup},
\mathcal{L}_{update},
\mathcal{L}_{query},
\mathcal{L}_{access}
)$$

The setup leakage is $$\mathcal{L}_{setup}
=
(
n,
m,
Dom
)$$ where $n$ denotes the number of encrypted IoMT records, $m$ is the
number of searchable-index entries, and $Dom$ represents the set of
participating administrative domains.

For each dynamic update, the adversary learns $$\mathcal{L}_{update}
=
(
Op,
CID,
|\Delta I|
)$$ where $Op$ denotes the update type, $CID$ is the modified ciphertext
identifier, and $|\Delta I|$ is the number of updated searchable-index
entries.

For each encrypted query, the adversary learns $$\mathcal{L}_{query}
=
(
|Q|,
|R|
)$$ where $|Q|$ denotes the number of queried keywords and $|R|$ is the
result size.

Finally, $$\mathcal{L}_{access}
=
Acc(Q)$$ captures the standard searchable-encryption access pattern,
namely the identifiers of encrypted records returned by a query.

No plaintext keywords, authorization attributes, authorization policies,
Version-Bound Authorization Profiles (VAPs), Policy-Bound Dynamic Search
Index (PDSI) entries, Incremental Authorization Synchronization (IAS)
messages, or plaintext IoMT records are revealed beyond the defined
leakage function.

Under the above assumptions and leakage model, the security objective of
MA-LB-PQ-VDSE is to guarantee that any probabilistic polynomial-time
adversary gains at most negligible advantage in distinguishing encrypted
IoMT records, inferring queried keywords, forging authorization states,
constructing valid verification proofs, or recovering post-quantum
session keys beyond the information explicitly disclosed by the leakage
function $\mathcal{L}$.

## Security Theorems

**Theorem 1 (Confidentiality of Multi-Authority IoMT Data).** Assume
that the underlying multi-authority CP-ABE scheme is IND-CPA secure,
ML-KEM is IND-CCA secure, AES-256-GCM is authenticated secure, and the
hash function $H$ is modeled as a random oracle. Then, any probabilistic
polynomial-time adversary obtains at most negligible advantage in
distinguishing the plaintext corresponding to an outsourced IoMT
ciphertext beyond the leakage function $\mathcal{L}$.

*Proof.* The proof follows a standard hybrid argument.

Game $G_0$ represents the real protocol execution.

In Game $G_1$, AES-256-GCM encryptions are replaced by encryptions of
uniformly random messages. By the IND-CPA security of AES-256-GCM,
$$\left|
Adv_{G_1}
-
Adv_{G_0}
\right|
\le
Adv_{AES}$$

Game $G_2$ replaces ML-KEM encapsulated session keys by uniformly random
keys. The adversary distinguishes $G_2$ from $G_1$ only by breaking the
IND-CCA security of ML-KEM.

Finally, Game $G_3$ replaces the encrypted session key generated by
MA-ABE with a random ciphertext. By the IND-CPA security of MA-ABE,
$$\left|
Adv_{G_3}
-
Adv_{G_2}
\right|
\le
Adv_{ABE}$$

Since the ciphertexts in $G_3$ are independent of the plaintext, the
adversary's distinguishing advantage is negligible.

Therefore, $$Adv
\le
Adv_{AES}
+
Adv_{ML-KEM}
+
Adv_{ABE}
=
negl(\lambda)$$

$\square$

**Theorem 2 (Search Token Privacy).**

Given the leakage function $\mathcal{L}$, the search token generated by
the proposed framework does not reveal plaintext keywords or
authorization information to any probabilistic polynomial-time
adversary. *Proof.*

Each search token is generated as $$T_Q=
\{
H(w_i\parallel VID_U)
\}$$

The authorization information is further bound by $$AuthRoot_U
=
H(
UID
\parallel
H(\mathcal S_U)
\parallel
VID_U
\parallel
H(\mathcal C_U)
)$$

Under the random oracle assumption, recovering the queried keyword
requires inverting $H$, while linking two search tokens requires finding
a collision under different authorization versions.

Whenever IAS updates $VID_U$, new search tokens become computationally
unlinkable to previous versions.

Consequently, the adversary learns only the predefined leakage function.

$\square$

**Theorem 3 (Correctness of Adaptive Authorization-Aware Search
Scheduling).** For any authorized search request, the proposed Adaptive
Authorization-Aware Search Scheduler (AASS) always selects a feasible
Fog Search Node that minimizes the predicted cryptographic search cost
among all candidate nodes satisfying the requested authorization scope.

*Proof.* Given a search request, AASS first eliminates all Fog Search
Nodes that do not contain the required authorized searchable-index
shards. Consequently, the remaining candidate set consists only of
feasible nodes capable of processing the query.

For each candidate node $FSN_j$, AASS computes the predicted search cost
$$SC_j=
\lambda_1C_j^{auth}
+\lambda_2C_j^{index}
+\lambda_3C_j^{verify}
+\lambda_4C_j^{sync}
+\lambda_5C_j^{queue}$$ which jointly captures the estimated
authorization evaluation, searchable-index traversal, verification,
synchronization, and queueing costs. The scheduler evaluates every
feasible candidate exactly once and maintains the node associated with
the smallest observed cost. After examining all candidates, the selected
node satisfies $$FSN^{*}
=
\arg\min_{FSN_j\in\mathcal{F}}
SC_j$$

Since every feasible candidate is evaluated under the same cost model
and the minimum-cost node is selected deterministically, no other
authorized Fog Search Node can achieve a lower predicted search cost.
Therefore, AASS always returns the optimal authorized search node,
thereby minimizing the estimated cryptographic search overhead while
preserving authorization correctness.

$\square$

**Theorem 4 (Correctness and Integrity of Incremental Authorization
Synchronization).** Assume that the hash function $H$ is collision
resistant and the consortium blockchain provides immutable storage.
Then, any probabilistic polynomial-time adversary cannot forge or
manipulate an Incremental Authorization Synchronization (IAS) message
that causes an unauthorized or inconsistent authorization state to be
accepted by a Fog Search Node except with negligible probability.

*Proof.* For every authorization update, the Authorization Index Manager
(AIM) constructs the synchronization message $$IAS_i=
(
\Delta VID_i,
\Delta C_i^{auth},
\Delta I_i,
\Delta Root_i,
Commit_i'
)$$ where $\Delta VID_i$ denotes the updated authorization version,
$\Delta C_i^{auth}$ is the updated authorization commitment,
$\Delta I_i$ represents the modified searchable-index entries,
$\Delta Root_i$ is the updated Merkle root, and $Commit_i'$ is the
updated policy commitment.

Upon receiving an IAS message, each Fog Search Node verifies that

1.  The authorization version is newer than its local version,
    $$VID_i' > VID_i$$

2.  The updated authorization commitment satisfies $$C_i^{auth'}
    =
    H(ID_i\parallel Dom_i\parallel H(\mathcal{A}_i)\parallel VID_i'\parallel RevRoot_i')$$

3.  The updated policy commitment is valid, $$Commit_i'
    =
    H(Root_i'\parallel PID_i'\parallel VID_i'\parallel AuthRoot_{DO})$$

4.  The updated commitment and authorization version are consistent with
    the immutable blockchain record.

Suppose an adversary attempts to forge or modify an IAS message. Such an
attack requires forging a valid authorization commitment, policy
commitment, Merkle root, or blockchain metadata. Forging the first three
requires breaking the collision resistance of $H$, whereas modifying the
blockchain contradicts its immutability. Consequently, any forged,
replayed, or tampered IAS message is detected and rejected during
synchronization. Therefore, IAS preserves the consistency of
authorization states, searchable-index entries, and integrity
commitments across distributed Fog Search Nodes except with negligible
probability.

$\square$

**Theorem 5 (Correctness and Integrity of Verifiable Retrieval).**
Assume that the hash function $H$ is collision resistant and the
consortium blockchain provides immutable storage. Then, any
probabilistic polynomial-time adversary controlling one or more Fog
Search Nodes cannot generate a forged search response that is accepted
by a legitimate Data User except with negligible probability.

*Proof.* For each search result, the Fog Search Node returns the
verification bundle $$\Pi_i=(CID_i,Root_i,Commit_i,\pi_i)$$ where
$CID_i$ is the IPFS content identifier, $Root_i$ is the Merkle root,
$Commit_i$ is the policy commitment, and $\pi_i$ is the Merkle
authentication path.

During Phase VIII, the Data User accepts a returned ciphertext only if
all of the following conditions hold:

1.  The Merkle authentication path satisfies
    $$\textsf{VerifyMerkle}(Root_i,\pi_i,CID_i)=1$$

2.  The policy commitment is valid, $$Commit_i=
    H(Root_i\parallel PID_i\parallel VID_i\parallel AuthRoot_U)$$

3.  The authorization version matches the current Version-Bound
    Authorization Profile, $$VID_i=VID_U$$

4.  The tuple $(CID_i,Commit_i,Root_i,VID_i)$ matches the immutable
    metadata stored on the consortium blockchain.

Suppose an adversary attempts to forge a valid search response. Such an
attack requires forging a Merkle authentication path, constructing a
valid policy commitment, replaying a stale authorization version, or
tampering with blockchain metadata. The first two require breaking the
collision resistance of $H$, while the latter two violate the version
consistency check or blockchain immutability. Therefore, a forged
response is accepted only with negligible probability. Hence, every
accepted search result is cryptographically bound to the latest
searchable index, authorization state, and blockchain commitment,
ensuring the correctness, integrity, and freshness of verifiable
retrieval.

$\square$

# Evaluation {#sec:evaluation}

This section evaluates the proposed framework through analytical
computation-cost comparison and experimental performance evaluation.
Four representative searchable encryption schemes are selected as
baselines. Specifically, Guo *et al*. [@ref35] represents verifiable
dynamic searchable encryption, XB-Muse [@ref36] represents
state-of-the-art dynamic searchable encryption, Thingom *et
al*. [@ref41] represents multi-authority attribute-based searchable
encryption, and Zhuang *et al*. [@ref52] represents lattice-based
post-quantum searchable encryption. Together, these baselines cover the
major research directions in searchable encryption, including dynamic
index maintenance, verifiable retrieval, multi-authority authorization,
and quantum-resistant cryptographic constructions.

## Computation Cost Analysis

Table [\[tab:cost\]](#tab:cost){reference-type="ref"
reference="tab:cost"} compares the complexity of the proposed framework
with the selected baselines. The comparison considers six representative
operations that dominate the end-to-end execution cost of searchable
encryption systems, namely trapdoor generation, encrypted search,
cross-domain search, keyword update, verification, and authorization
synchronization.

The notation used in the analysis is summarized below.

::: {#tab:cost-notation}
  **Notation**           **Description**
  ---------------------- -----------------------------------------------------------
  $q$                    Number of queried keywords
  $d$                    Number of participating administrative domains
  $n_{\mathrm{eff}}$     Number of authorized candidate ciphertexts
  $r$                    Number of returned search results
  $k$                    Number of updated keywords
  $\delta$               Number of authorization/revocation updates
  $a_w$                  Number of encrypted entries associated with keyword $w$
  $x$                    Number of candidate documents after conjunctive filtering
  $t$                    Number of keywords in an updated document
  $l$                    Number of attributes in an access policy
  $u$                    Number of user attributes
  $e$                    Number of rows in an LSSS access structure
  $T_H$                  One hash computation
  $T_{\mathrm{PRF}}$     One pseudorandom function evaluation
  $T_{\mathrm{BF}}$      One bitmap/Bloom-filter lookup
  $T_{\mathrm{MT}}$      One Merkle-tree operation
  $T_{\mathrm{Sig}}$     One digital-signature verification
  $T_{\mathrm{Exp}}$     One modular exponentiation (or scalar multiplication)
  $T_P$                  One bilinear pairing operation
  $T_{\mathrm{Samp}}$    One lattice sampling operation
  $T_{\mathrm{Basis}}$   One lattice basis delegation/update operation

  : Notation used in the computation-cost analysis.
:::

::: table*
  ---------------------------- ----------------- ------------ ----------------- ------------------ ---------------------
  **Scheme**                     **Trapdoor**     **Search**     **Keyword**     **Verification**    **Authorization**
                                **Generation**                   **Update**                         **Synchronization**
  Guo *et al*. [@ref35]            $O(d)T_P$                                                       
  $(T_P+T_H)$                                                                                      
  $(T_P+T_H)$                      $O(x)T_H$         N/A                                           
  XB-Muse [@ref36]                 $O(d)T_P$                                                       
  $(T_P+T_E)$                   $O(1)(T_P+T_H)$      N/A             N/A                           
  Thingom *et al*. [@ref41]                                                                        
  $(T_H+T_E)+dT_B$                                                                                 
  $(T_E+T_B)$                         N/A            N/A             N/A                           
  Zhuang *et al*. [@ref52]        $O(dl)T_S$                                                       
  $(T_S+T_H)$                   $O(1)(T_S+T_D)$      N/A       $O(1)(T_S+T_D)$                     
  **Proposed**                     $O(q)T_P$                                                       
  $+O(n_{\rm eff})(T_F+T_H)$                                                                       
  $+O(\log n)T_M$                                                                                  
  $+O(d)T_{Sig}$                                                                                   
  $+O(\log d)T_M$                                                                                  
  ---------------------------- ----------------- ------------ ----------------- ------------------ ---------------------
:::

Table [\[tab:cost\]](#tab:cost){reference-type="ref"
reference="tab:cost"} compares the dominant computation costs under a
cross-domain search setting. Since the baseline schemes do not natively
support cross-domain retrieval, a user must issue separate trapdoors and
independent search requests for each participating domain. As a result,
their trapdoor generation and search costs increase linearly with the
number of domains $d$. This overhead becomes more significant for
attribute-based and lattice-based schemes, where repeated
exponentiation, pairing, or lattice-sampling operations are required.

In contrast, the proposed framework generates a single
authorization-bound trapdoor for each multi-domain query. The same
trapdoor can be reused across participating domains, while each fog
search node enforces domain-specific authorization locally. Moreover,
authorization-aware bitmap filtering removes unauthorized ciphertexts
before encrypted matching, so the online search cost depends mainly on
the effective authorized candidate set $n_{\mathrm{eff}}$ rather than
the total encrypted index size across all domains. Although the proposed
framework introduces additional verification and synchronization costs
to support auditable retrieval and dynamic authorization, these
operations are incremental and avoid global index reconstruction.
Therefore, the proposed design reduces redundant cross-domain trapdoor
generation and repeated search execution while supporting verifiable,
authorization-aware, and post-quantum-secure IoMT data sharing.

## Performance Evaluation

### Experimental Setup

The proposed framework was implemented in Python 3.11 and evaluated on
Amazon AWS EC2 c6i.xlarge instances, each equipped with 4 vCPUs and 8 GB
RAM. Four Fog Search Nodes and one cloud server were deployed within an
AWS Virtual Private Cloud (VPC) to emulate a distributed cross-domain
IoMT healthcare environment. Each FSN independently maintains
authorization-aware searchable indexes and performs encrypted search,
while the cloud server stores encrypted EHRs and blockchain metadata.

The framework employs ML-KEM-768 for post-quantum secure key
establishment, AES-256-GCM for symmetric encryption, SHA-256 for hashing
and Merkle-tree construction, and Hyperledger Fabric v2.5 for
maintaining authorization commitments and audit records. Search indexes
are implemented using bitmap-based authorization-aware filtering
combined with authenticated Merkle trees to support efficient encrypted
retrieval and verification.

Experiments were conducted using the MIMIC-IV clinical dataset
 [@ref55], from which encrypted searchable indexes containing
$10^4$--$10^6$ electronic health records were generated and uniformly
distributed across four administrative healthcare domains. Unless
otherwise specified, each query contains five keywords, and every
experiment reports the average of 30 independent runs with 95%
confidence intervals.

The proposed framework was compared with four representative searchable
encryption schemes: Guo *et al*. [@ref35] (verifiable dynamic searchable
encryption), XB-Muse [@ref36] (dynamic searchable encryption), Thingom
*et al*. [@ref41] (multi-authority searchable encryption), and Zhuang
*et al*. [@ref52] (lattice-based post-quantum searchable encryption).
The evaluation focuses on trapdoor generation, encrypted search
efficiency, cross-domain search scalability, keyword update performance,
retrieval verification, authorization synchronization, and
authorization-aware load balancing under increasing workloads.

### **Experiment 1: Trapdoor Generation Latency** {#exp:trapdoor .unnumbered}

This experiment evaluates the trapdoor generation latency as the number
of queried keywords increases from 1 to 20. The proposed framework is
compared with Guo *et al*. [@ref35], XB-Muse [@ref36], Thingom *et
al*. [@ref41], and Zhuang *et al*. [@ref52]. Since ML-KEM is executed
only during session establishment, only online trapdoor generation is
measured.

<figure id="fig:exp1" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp1_trapdoor.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Trapdoor generation latency versus queried
keywords.</figcaption>
</figure>

Fig. [2](#fig:exp1){reference-type="ref" reference="fig:exp1"} compares
the trapdoor generation latency under increasing query complexity.
Although the proposed framework incurs slightly higher latency than
classical dynamic searchable encryption schemes because of
authorization-aware trapdoor construction, it remains substantially more
efficient than pairing-based and lattice-based approaches while
providing quantum-resistant secure communication and multi-domain
authorization.

### **Experiment 2: Search Latency** {#exp:search .unnumbered}

This experiment evaluates encrypted search latency as the searchable
index grows from $10^4$ to $10^6$ encrypted records. The same four
baseline schemes are used for comparison.

<figure id="fig:exp2" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp2_search.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Encrypted search latency versus dataset size.</figcaption>
</figure>

Fig. [3](#fig:exp2){reference-type="ref" reference="fig:exp2"}
demonstrates that authorization-aware bitmap filtering significantly
reduces online search overhead by eliminating unauthorized ciphertexts
before encrypted matching. Consequently, the proposed framework achieves
the lowest search latency as the dataset size increases.

### **Experiment 3: Cross-Domain Search Scalability** {#exp:crossdomain .unnumbered}

This experiment evaluates search latency when the number of
participating healthcare domains increases from 2 to 10. Since the
baseline schemes do not natively support cross-domain search, they
perform independent searches over each domain and aggregate the results.

<figure id="fig:exp3" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp3_crossdomain.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Cross-domain search latency versus number of
domains.</figcaption>
</figure>

Fig. [4](#fig:exp3){reference-type="ref" reference="fig:exp3"} shows
that the proposed framework scales significantly better than the
baselines by reusing a single authorization-bound trapdoor across
multiple domains and performing domain-aware authorization pruning
before encrypted search.

### **Experiment 4: Verification Overhead** {#exp:verify .unnumbered}

This experiment evaluates retrieval verification latency as the number
of returned encrypted records increases from 10 to 1000. Since only Guo
*et al*. [@ref35] provides verifiable search, it serves as the primary
comparison.

<figure id="fig:exp4" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp4_verify.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Verification latency versus returned search
results.</figcaption>
</figure>

Fig. [5](#fig:exp4){reference-type="ref" reference="fig:exp4"}
illustrates that incremental Merkle-proof verification incurs only
logarithmic authentication overhead while maintaining complete
search-result integrity.

### **Experiment 5: Dynamic Keyword Update** {#exp:update .unnumbered}

This experiment measures keyword update latency as the number of updated
keywords increases from $10^2$ to $10^5$. The proposed framework is
compared with Guo *et al*. [@ref35], XB-Muse [@ref36], and Zhuang *et
al*. [@ref52].

<figure id="fig:exp5" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp5_update.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Keyword update latency versus updated keywords.</figcaption>
</figure>

Fig. [6](#fig:exp5){reference-type="ref" reference="fig:exp5"}
demonstrates that incremental Merkle-tree maintenance avoids global
index reconstruction and achieves competitive update performance while
preserving authenticated search indexes.

### **Experiment 6: Authorization Synchronization** {#exp:sync .unnumbered}

This experiment evaluates authorization synchronization latency under
increasing numbers of authorization updates ranging from $10^2$ to
$10^5$. Zhuang *et al*. [@ref52] is used as the representative baseline
supporting dynamic membership updates.

<figure id="fig:exp6" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp6_sync.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Authorization synchronization latency versus authorization
updates.</figcaption>
</figure>

Fig. [7](#fig:exp6){reference-type="ref" reference="fig:exp6"} shows
that incremental authorization synchronization efficiently propagates
policy changes without rebuilding searchable indexes, resulting in
stable synchronization latency under large-scale revocation events.

### Experiment 7: Search Throughput under Increasing Workload {#exp:throughput}

This experiment evaluates the effectiveness of the proposed
authorization-aware load balancer. Four configurations are considered:
(i) No Load Balancing, (ii) Round Robin, (iii) Least Loaded, and (iv)
Proposed Scheduler. The concurrent search workload increases from 100 to
5000 requests.

<figure id="fig:exp7" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp7_throughput.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Search throughput versus concurrent requests.</figcaption>
</figure>

Fig. [8](#fig:exp7){reference-type="ref" reference="fig:exp7"} shows
that the proposed scheduler achieves the highest throughput by jointly
considering authorization locality, queue length, and node workload,
thereby minimizing unnecessary cross-node communication and balancing
encrypted search requests.

### **Experiment 8: Load-Balancing Effectiveness** {#exp:balance .unnumbered}

This experiment evaluates workload distribution across Fog Search Nodes
under increasing concurrent search requests. The same four
load-balancing strategies are compared. The standard deviation of node
utilization is adopted as the load-balance metric.

<figure id="fig:exp8" data-latex-placement="!t">
<span class="image placeholder"
data-original-image-src="images/fig_exp8_balance.pdf"
data-original-image-title="" width="\columnwidth"></span>
<figcaption>Standard deviation of Fog Search Node
utilization.</figcaption>
</figure>

Fig. [9](#fig:exp8){reference-type="ref" reference="fig:exp8"}
demonstrates that the proposed scheduler maintains the lowest
utilization variance among all Fog Search Nodes. As the workload
increases, authorization-aware scheduling effectively prevents node
congestion and improves overall resource utilization, thereby enabling
stable encrypted-search performance for large-scale cross-domain IoMT
deployments.

# Acknowledgment

This work was supported by the Thammasat University Research Fund under
Contract TUFT 032/2568.

::: thebibliography
99

J. Malamas, V. Kotzanikolaou, P. Dasaklis, and M. Burmester, "A
hierarchical multi blockchain for fine grained access to medical data,"
*IEEE Access*, vol. 8, pp. 134393--134412.

H. Gao, Z. Ma, S. Luo, Y. Xu, and Z. Wu, "BSSPD: a blockchain-based
security sharing scheme for personal data with fine-grained access
control," *Wireless Communications and Mobile Computing*, 2021.

S. Fugkeaw, "A Lightweight Policy Update Scheme for Outsourced Personal
Health Records Sharing," *IEEE Access*, vol. 9, pp. 54862--54871, 2021.

J. Chen, X. Yin, and J. Ning, "A fine-grained and secure health data
sharing scheme based on blockchain," *Transactions on Emerging
Telecommunications Technologies*, e4510.

J. Yuan, Y. Ma, W. Luo, and G. Han, "B-SSMD: A Fine-Grained Secure
Sharing Scheme of Medical Data Based on Blockchain," *Security and
Communication Networks*, 2022.

Z. Zhang, J. Wang, Y. Wang, Y. Su, and X. Chen, "Towards efficient
verifiable forward secure searchable symmetric encryption," in *Proc.
Eur. Symp. Res. Comput. Secur.*, Sep. 2019, pp. 304--321.

Z. Liu, T. Li, P. Li, C. Jia, and J. Li, "Verifiable searchable
encryption with aggregate keys for data sharing system," *Future Gener.
Comput. Syst.*, vol. 78, pp. 778--788, Jan. 2018. \[Online\]. Available:
http://dx.doi.org/10.1016/j.future.2017.02.024

Z. Shi, X. Fu, X. Li, and K. Zhu, "ESVSSE: Enabling efficient, secure,
verifiable searchable symmetric encryption," *IEEE Trans. Knowl. Data
Eng.*, vol. 34, no. 7, pp. 3241--3254, Jul. 2022, doi:
10.1109/TKDE.2020.3025348.

A. Wu, A. Yang, W. Luo, and W. Jinghang, "Enabling traceable and
verifiable multi-user forward secure searchable encryption in hybrid
cloud," *IEEE Trans. Cloud Comput.*, early access, Apr. 26, 2022.

Q. Gan, J. K. Liu, X. Wang, *et al.*, "Verifiable searchable symmetric
encryption for conjunctive keyword queries in cloud storage," *Front.
Comput. Sci.*, 16, 166820 (2022).

S. Hu, C. Cai, Q. Wang, C. Wang, X. Luo, and K. Ren, "Searching an
encrypted cloud meets blockchain: A decentralized, reliable and fair
realization," in *Proc. IEEE Conf. Comput. Commun. (INFOCOM)*, Apr.
2018, pp. 792--800.

T. Wang *et al.*, "An efficient verifiable searchable encryption scheme
with aggregating authorization for blockchain-enabled IoT," *IEEE
Internet Things J.*, vol. 9, no. 20, pp. 20666--20680, Oct. 2022.

R. Du, N. Liu, M. Li, and J. Tian, "Block verifiable dynamic searchable
encryption using redactable blockchain," *Journal of Information
Security and Applications*, vol. 75, 2023.

B. Chen, T. Xiang, D. He, H. Li and K.-K. R. Choo, "BPVSE: Publicly
Verifiable Searchable Encryption for Cloud-Assisted Electronic Health
Records," *IEEE Transactions on Information Forensics and Security*,
vol. 18, pp. 3171--3184, 2023.

C. Huang, D. Liu, A. Yang, R. Lu and X. Shen, "Multi-client Secure and
Efficient DPF-based Keyword Search for Cloud Storage," *IEEE
Transactions on Dependable and Secure Computing*.

L. Xu, X. Yuan, R. Steinfeld, C. Wang, and C. Xu, "Multi-writer
searchable encryption: An lwe-based realization and implementation," in
*Proc. of ACM CCS*, 2019, pp. 122--133.

J. Gharehchamani, Y. Wang, D. Papadopoulos, M. Zhang, and R. Jalili,
"Multi-user dynamic searchable symmetric encryption with corrupted
participants," *IEEE Trans. Dependable Secure Comput.*, 2021.

X. Zhang, C. Huang, Y. Su, J. Qin, and X. Shen, "Divertible searchable
symmetric encryption for secure cloud storage," in *Proc. of IEEE
GLOBECOM*, 2022, pp. 3785--3790.

X. Yang, G. Chen, M. Wang, T. Li and C. Wang, "Multi-Keyword
Certificateless Searchable Public Key Authenticated Encryption Scheme
Based on Blockchain," *IEEE Access*, vol. 8, pp. 158765--158777, 2020.

J. Lapmoon and S. Fugkeaw, "A Verifiable and Secure Industrial IoT Data
Deduplication Scheme With Real-Time Data Integrity Checking in
Fog-Assisted Cloud Environments," *IEEE Access*, vol. 13, pp.
11969--11988, 2025.

S. Fugkeaw, R. Prasad Gupta and K. Worapaluk, "Secure and Fine-Grained
Access Control With Optimized Revocation for Outsourced IoT EHRs With
Adaptive Load-Sharing in Fog-Assisted Cloud Environment," *IEEE Access*,
vol. 12, pp. 82753--82768, 2024.

F. Li *et al.*, "Towards Efficient Verifiable Boolean Search Over
Encrypted Cloud Data," *IEEE Transactions on Cloud Computing*, vol. 11,
no. 1, pp. 839--853, 1 Jan.--Mar. 2023.

Q. Wang, X. Zhang, J. Qin, J. Ma, and X. Huang, "A Verifiable Symmetric
Searchable Encryption Scheme Based on the AVL Tree," *The Computer
Journal*, vol. 66, no. 1, Jan. 2023, pp. 174--183,

L. Ji, J. Li, Y. Zhang and Y. Lu, "Verifiable Searchable Symmetric
Encryption Over Additive Homomorphism," *IEEE Transactions on
Information Forensics and Security*, vol. 20, pp. 1320--1332, 2025.

S. Fugkeaw, L. Hak and T. Theeramunkong, "Achieving Secure, Verifiable,
and Efficient Boolean Keyword Searchable Encryption for Cloud Data
Warehouse," *IEEE Access*, vol. 12, pp. 49848--49864, 2024.

L. Xu, S. Sun, X. Yuan, J. K. Liu, C. Zuo and C. Xu, "Enabling
Authorized Encrypted Search for Multi-Authority Medical Databases,"
*IEEE Transactions on Emerging Topics in Computing*, vol. 9, no. 1, pp.
534--546, 1 Jan.--Mar. 2021.

J. Bethencourt, A. Sahai, and B. Waters, "Ciphertext-policy
attribute-based encryption," in *Proc. IEEE Symp. Security and Privacy*,
2007, pp. 321--334.

J. Yu, S. Liu, M. Xu, H. Guo, F. Zhong and W. Cheng, "An Efficient
Revocable and Searchable MA-ABE Scheme With Blockchain Assistance for
C-IoT," *IEEE Internet of Things Journal*, vol. 10, no. 3, pp.
2754--2766, 1 Feb. 2023.

H. Dou *et al.*, "Dynamic Searchable Symmetric Encryption With Strong
Security and Robustness," *IEEE Transactions on Information Forensics
and Security*, vol. 19, pp. 2370--2384, 2024.

Y. Ge, Y. Gao, J. Ning, J. Ma and X. Chen, "Verifiable Multilevel
Dynamic Searchable Encryption With Forward and Backward Privacy in
Cloud-Assisted IoT," *IEEE Internet of Things Journal*, vol. 11, no. 24,
pp. 40861--40874, 15 Dec. 2024.

D. Li, X. Zhao, H. Li and K. Fan, "Volume-Hiding Multidimensional
Verifiable Dynamic Searchable Symmetric Encryption Scheme for Cloud
Computing," *IEEE Internet of Things Journal*, vol. 11, no. 23, pp.
37437--37451, 1 Dec. 2024.

X. Zhu, J. Zhou, Y. Dai, P. Shen, S. Kasra Kermanshahi and J. Hu, "A
Verifiable and Efficient Symmetric Searchable Encryption Scheme for
Dynamic Dataset With Forward and Backward Privacy," *IEEE Transactions
on Dependable and Secure Computing*, vol. 22, no. 3, pp. 2741--2755,
May--Jun. 2025.

M. Li, C. Jia, R. Du and W. Shao, "Forward and Backward Secure
Searchable Encryption Scheme Supporting Conjunctive Queries Over
Bipartite Graphs," *IEEE Transactions on Cloud Computing*, vol. 11, no.
1, pp. 1091--1102, 1 Jan.--Mar. 2023.

M. Li, C. Jia, R. Du, W. Shao and G. Ha, "DSE-RB: A Privacy-Preserving
Dynamic Searchable Encryption Framework on Redactable Blockchain," *IEEE
Transactions on Cloud Computing*, vol. 11, no. 3, pp. 2856--2872,
Jul.--Sep. 2023.

C. Guo, W. Li, X. Tang, K.-K. R. Choo and Y. Liu, "Forward Private
Verifiable Dynamic Searchable Symmetric Encryption With Efficient
Conjunctive Query," *IEEE Transactions on Dependable and Secure
Computing*, vol. 21, no. 2, pp. 746--763, Mar.--Apr. 2024.

Q. Jiang, X. Yang, S. Chen, S. Qi, F. Song and Z. Fu, "XB-Muse:
Practical Multiuser Dynamic Searchable Symmetric Encryption for Adaptive
Revocation," *IEEE Internet of Things Journal*, vol. 12, no. 14, pp.
26486--26499, 15 Jul. 2025, doi: 10.1109/JIOT.2025.3561287.

X. Wang, J. Ma, X. Liu, Y. Miao, Y. Liu and R. H. Deng,
"Forward/Backward and Content Private DSSE for Spatial Keyword Queries,"
*IEEE Transactions on Dependable and Secure Computing*, vol. 20, no. 4,
pp. 3358--3370, Jul.--Aug. 2023.

X. Zhang, C. Huang, Y. Su and J. Qin, "Secure, Dynamic, and Efficient
Keyword Search With Flexible Merging for Cloud Storage," *IEEE
Transactions on Services Computing*, vol. 17, no. 5, pp. 2822--2835,
Sep.--Oct. 2024.

D. X. Song, D. Wagner, and A. Perrig, "Practical techniques for searches
on encrypted data," in *Proc. IEEE Symp. Security and Privacy*, 2000,
pp. 44--55.

R. Curtmola, J. Garay, S. Kamara, and R. Ostrovsky, "Searchable
symmetric encryption: Improved definitions and efficient constructions,"
in *Proc. ACM CCS*, 2006, pp. 79--88.

C. Thingom et al., "Secure and Privacy-Preserving Post-Quantum
Attribute-Based Searchable Encryption for Edge-Driven Transportation
Systems," IEEE Transactions on Consumer Electronics, vol. 72, no. 1, pp.
1865--1875, Feb. 2026, doi: 10.1109/TCE.2025.3632071.

Y. Yang, J. Ma, X. Liu, and R. H. Deng, "Revocable dynamic searchable
encryption with forward and backward privacy," *IEEE Transactions on
Dependable and Secure Computing*, early access, 2025.

B. Chen, T. Xiang, D. He, H. Li, and K.-K. R. Choo, "BPVSE: Publicly
Verifiable Searchable Encryption for Cloud-Assisted Electronic Health
Records," *IEEE Transactions on Information Forensics and Security*,
vol. 18, pp. 3171--3184, 2023.

S. Fugkeaw, K. Tangtanawirut, P. Rattanasrisuk and A. Changtor,
\"MK-WISE: Secure and Efficient Multi-Keyword Wildcard ABSE with
Keyword-Level Revocation for Device--Edge--Cloud EHRs Data Sharing,\"
*IEEE Transactions on Network and Service Management*.

J. Wu, K. Zhang, J. Ning, H. Chen, L. Zhang and Z. Ying,
\"Multi-Writer/Reader Forward and Backward Private DSSE With Bilateral
Selection,\" in IEEE Transactions on Dependable and Secure Computing,
vol. 23, no. 2, pp. 2444-2457, March-April 2026, doi:
10.1109/TDSC.2025.3627926.

L. Chen, Y. Wu, H. Zhang, J. Weng and Z. Liu, \"Verifiable Multi-User
Dynamic Searchable Symmetric Encryption With Forward and Backward
Privacy Feasible for Cloud Storage,\" in IEEE Transactions on
Information Forensics and Security, vol. 21, pp. 3797-3811, 2026, doi:
10.1109/TIFS.2026.3681434.

H. Gao, H. Huang, L. Xue, F. Xiao, and Q. Li, "Blockchain- enabled
fine-grained searchable encryption with cloud--edge com- puting for
electronic health records sharing," IEEE Internet of Things Journal,
vol. 10, no. 20, pp. 18414--18425, Oct. 2023, doi:
10.1109/JIOT.2023.3279893.

M. Perera and S. Fugkeaw, \"Enabling Fault-Tolerant and Load-Balanced
Multi-Query Searchable Encryption With Multi-Level Revocation in
Edge-Fog-Cloud for Electronic Health Records,\" in IEEE Open Journal of
the Communications Society, vol. 7, pp. 6964-6983, 2026, doi:
10.1109/OJCOMS.2026.3706304.

Y. Miao et al., "Time-controllable keyword search scheme with efficient
revocation in mobile e-health cloud," IEEE Transactions on Mobile
Computing, vol. 23, no. 5, pp. 3650--3665, May 2024.

L. Hak and S. Fugkeaw, \"SSL-XIoMT: Secure, Scalable, and Lightweight
Cross-Domain IoMT Sharing With SSI and ZKP Authentication,\" in IEEE
Open Journal of the Computer Society, vol. 6, pp. 714-725, 2025, doi:
10.1109/OJCS.2025.3570087.

B. D. Deebak and S. O. Hwang, \"Blockchain Authorized Privacy-Preserving
Framework Using Edge Computing for the Cloud-Assisted Internet of
Medical Things,\" in IEEE Transactions on Cloud Computing, vol. 14, no.
2, pp. 445-462, April-June 2026, doi: 10.1109/TCC.2026.3656828.

E.-S. Zhuang, C.-Y. Lin, C.-I. Fan, A. Karati, and D. Das, "Multi-
authority attribute-based multi-keyword searchable encryption with dy-
namic membership from lattices," in Proc. IEEE Conf. Dependable and
Secure Computing (DSC), Taipei, Taiwan, 2025, pp. 1--6, doi:
10.1109/DSC65356.2025.11260864.

L. Chen, Y. Liu, H. Zhang and J. Weng, "Multi-Authority Attribute- Based
Searchable Encryption With Attribute Revocation for Internet of
Vehicles," IEEE Transactions on Vehicular Technology, early access,
2025, doi: 10.1109/TVT.2025.3629863.

M. Perera and S. Fugkeaw, "LV-PQ-ABSE: A Lightweight Verifiable
Post-Quantum Attribute-Based Searchable Encryption Scheme with Hy- brid
Indexing and Provenance-Aware Verification for IoT-Based EHRs," in IEEE
Internet of Things Journal, doi: 10.1109/JIOT.2026.3695855. Y. Cao et
al., "Enabling Puncturable Encrypted Search Over Lattice for
Privacy-Preserving in Mobile Cloud," IEEE Transactions on Mobile
Computing, early access, 2026, doi: 10.1109/TMC.2026.3682118.

Johnson, A., Bulgarelli, L., Pollard, T., Gow, B., Moody, B., Horng, S.,
Celi, L. A., & Mark, R. (2024). MIMIC-IV (version 3.1). PhysioNet.
RRID:SCR_007345. https://doi.org/10.13026/kpb9-mt58
:::
