
===== [ Page 1 ] =====

Multi-Authority Attribute-Based Multi-Keyword
Searchable Encryption with Dynamic Membership
from Lattices
Er-Shuo Zhuang
Information Security Research
Center
National Sun Yat-sen University
Kaohsiung, Taiwan
zhuanges@gmail.com
Chia-Yu Lin
Department of Computer Science
and Engineering
National Sun Yat-sen University
Kaohsiung, Taiwan
xcvb880224@gmail.com
Chun-I Fan*
Department of Computer Science
and Engineering
National Sun Yat-sen University
Kaohsiung, Taiwan
cifan@mail.cse.nsysu.edu.tw
Arijit Karati
Department of Computer Science and Engineering
National Sun Yat-sen University
Kaohsiung, Taiwan
arijit.karati@mail.cse.nsysu.edu.tw
Debasis Das
Department of Computer Science and Engineering
Indian Institute of Technology Jodhpur
Rajasthan, India
debasis@iitj.ac.in
Abstract—With the growing need for secure cloud storage and
the threat of quantum attacks, we propose a post-quantum se-
cure lattice-based multi-authority attribute-based multi-keyword
searchable encryption scheme with dynamic membership. Based
on the decisional learning with errors assumption, the pro-
posed scheme resists quantum adversaries while supporting
flexible multi-keyword search, decentralized authority to avoid
key escrow, and dynamic attribute updates without affecting
other users. It enables users to independently generate search
tokens, allowing offline authorities and reducing communication
overhead. Despite higher encryption costs, experimental results
demonstrate that search and decryption remain efficient com-
pared to existing post-quantum lattice-based solutions. The pro-
posed scheme achieves strong data confidentiality and keyword
privacy in the post-quantum setting.
Index Terms—Lattice-Based Cryptography, Attribute-Based
Encryption, Searchable Encryption, Dynamic Membership Man-
agement, Multi-Authority, Post-Quantum Cryptography
I. INTRODUCTION
Song et al. [1] proposed the first searchable encryption
scheme. Boneh et al. [2] later introduced public-key encryption
with keyword search (PEKS), enabling secure search via trap-
doors. Meanwhile, Sahai and Waters [3] proposed attribute-
based encryption (ABE), which provides fine-grained access
control by tying decryption rights to user attributes. ABE has
two variants: Key-Policy ABE (KP-ABE) [4] and Ciphertext-
Policy ABE (CP-ABE) [5].
Although ABE offers strong access control, it struggles with
scalability and dynamic user management. Fan et al. [6] in-
troduced dynamic membership to support attribute revocation.
Traditional ABE schemes also depend on a single trusted
*Corresponding author: Chun-I Fan.
key generation center (KGC), leading to centralization and
key escrow concerns. Multi-authority ABE (MA-ABE) [7]–
[9] mitigates these risks by distributing trust across multiple
authorities.
Another pressing issue is the threat posed by quantum
computing. Shor’s algorithm [10] compromises classical cryp-
tosystems, driving the development of post-quantum cryptog-
raphy (PQC). Lattice-based cryptography is a leading PQC
candidate due to its efficiency and strong security assumptions.
Prior work has explored lattice-based ABE [11]–[13], and Liu
et al. [14] incorporated keyword search into such frameworks.
A. Contributions
Our proposed scheme addresses these limitations with the
following features:
• Multi-Authority Architecture: Employs a CP-ABE
framework with multiple authorities to eliminate key
escrow and enhance trust and scalability.
• Advanced Functionalities: Supports multi-keyword
search, dynamic membership updates, and offline search
token generation, enabling practical and fine-grained ac-
cess control in cloud environments.
• Post-Quantum Security: Leverages hard lattice prob-
lems to ensure quantum resistance and collusion resis-
tance.
II. PRELIMINARIES
We introduce some background knowledge here.
A. Lattice Sampling and Trapdoor Algorithms
We introduce some trapdoor generation algorithms and
sampling algorithms from Micciancio and Peikert [15].
979-8-3315-1538-6/25/$31.00 ©2025 IEEE
(name)
2025 IEEE Conference on Dependable and Secure Computing (DSC) | 979-8-3315-1538-6/25/$31.00 ©2025 IEEE | DOI: 10.1109/DSC65356.2025.11260864
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.


===== [ Page 2 ] =====

Definition II.1 (TrapGen ). Let n ∈ Z
+, q be prime, m =
⌈6n log q⌉, and σ > 0. The algorithm TrapGen(n, m, q, σ)
outputs (A, TA), where A ∈ Z
n×m
q is statistically close to
uniform and TA ∈ Z
m×m is a trapdoor basis of Λ
⊥
q (A) with
∥ ˜
TA∥ ≤
√
n log q with high probability.
Definition II.2 (SamplePre). Given (A, TA, u, σ) with σ >
∥ ˜
TA∥ · ω(
√
log m), the algorithm SamplePre outputs e ∈
Λ
u
q (A) distributed statistically close to DΛu
q (A),σ.
Definition II.3 (SampleLeft ). Given (A ∈ Z
n×m
q , M ∈
Z
n×m
′
q , TA, u, σ), the algorithm SampleLeft outputs e ∈
Z
m+m
′
sampled from a distribution statistically close to
DΛu
q ([A|M]),σ such that [A|M] · e = u mod q.
Definition II.4 (SampleR). Given security parameter m, the
algorithm SampleR(1
m) outputs an invertible matrix R ∈
Z
m×m
q sampled from a distribution Dm×m.
Definition II.5 (BasisDel). Given (A, R, TA, σ), where R ∈
Z
m×m
q is invertible, the algorithm BasisDel outputs a trapdoor
basis TF for Λ
⊥
q (F) where F = AR
−1.
B. Access Structure
During encryption, the sender specifies an access structure
embedded in the ciphertext to control user access. Let S be
the universe of attributes and SID ⊆ S the attribute set of user
ID. The access structure τ is represented as a tree whose leaf
nodes correspond to attributes in SC ⊆ S, and whose internal
nodes are limited to AND or OR gates.
C. Bloom Filter
A Bloom filter is a probabilistic data structure utilized for
efficient membership tests of set elements. By utilizing an
l-bit array and k hash functions, denoted as BF (l, k), it can
rapidly determine whether an element is present in a set or not.
A positive result from a Bloom filter query indicates a high
probability that the element is present in the set. However,
there is a possibility of false positives. The false positive rate
is related to the size of the array and the number of hash
functions.
D. System Model
The system model of the proposed scheme is shown in
Fig. 1. The scheme consists of six roles as follows:
• Initializer: One of the attribute authorities. It collects and
publishes updated public keys and global parameters. It
cannot access master private keys of other authorities.
• Public Key Bulletin Board (PKB): Honest-but-curious
entity that publishes public keys and parameters.
• Attribute Authority (AA): Each AA generates pub-
lic/master keys and assists in user key generation and
updates.
• Cloud Server (CS): Honest-but-curious storage and
search provider, responsible for storing encrypted data
and processing search queries without learning sensitive
information.
• Data Owner (DO): Encrypts and uploads ciphertexts,
defining access policies to ensure only authorized users
can access the data.
• Data User (DU): Generates search tokens and retrieves
ciphertext, then decrypts data if their attributes satisfy the
access policy.
Fig. 1: The System Model
III. CONSTRUCTION
The notations used are summarized in Table I.
TABLE I: The Notations
Notation Meaning
D the set of all attribute authorities
U the set of all attributes
L the set of all enrolled users’ identities
H a hash function
AAd the d-th attribute authority
ai the i-th attribute
| · | the number of the elements in some set
ID the identity of some user
χ a Gaussian distribution
Ud the set of attributes monitored by AAd
U
ID the attribute set of ID
U
ID
d the attribute set of ID monitored by AAd
UC the set of attributes associated with CT
DC the attribute authorities monitoring UC
P Kd the public key of AAd
M Kd the master private key of AAd
SK
ID
d the partial private key of ID for AAd
SKID the private key of ID
W the keyword set
ki the i-th keyword
A. Setup
GP ← Setup(λ, D, U ): Given a security parameter λ, the
set of all attribute authorities D, and the set of all attributes
U . Then, the Initializer performs the steps below to generate
the global public parameters GP :
1) Select a prime number q, two positive integers n, m, a
positive Gaussian parameter σ, and a Gaussian distribu-
tion χ.
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.


===== [ Page 3 ] =====

2) Select a hash function H0 : {0, 1}
∗ → Z
n×m
q .
3) Select k hash functions Hi : {0, 1}
∗ → Zq, where 1 ≤
i ≤ k.
4) Let L denote the set of all enrolled users’ identities.
5) Randomly choose a vector u ∈ Z
n
q .
6) Output the global public parameters GP =
{q, n, m, σ, H0, {Hi}1≤i≤k, D, U, L, χ, u}.
B. AASetup
(P Kd, M Kd) ← AASetup(GP ): After the Initializer pub-
lishes GP , each AAd performs the following steps to generate
their public key P Kd and master secret key M Kd:
1) Let Ud denote the set of attributes monitored by AAd.
For each attribute ai ∈ Ud, run TrapGen(n, m, q, σ) to
generate Ad,i ∈ Z
n×m
q and TAd,i ∈ Z
m×m
q , where ai
denotes the i-th attribute.
2) Set Ad = {Ad,i}ai∈Ud and P Kd = ∅. Publish the public
key P Kd.
3) Set {TAd,i }ai∈Ud as the master secret key M Kd.
Note: Through the AASetup algorithm, each attribute au-
thority independently generates its own key pair, achieving
a decentralized structure with the multi-authority feature.
C. Enroll
(P Kd, SK
ID
d ) ← Enroll(GP, P Kd, M Kd, ID, U
ID
d ): The
user enrollment is executed by each AAd involving the user’s
ID and a set of attributes U
ID
d that are monitored by AAd.
The private key for U
ID
d is generated by each AAd through
the steps below:
1) ∀ai ∈ U
ID
d :
a) Invoke SampleR(1
m) to sample an invertible matrix
R
ID
d,i ∈ Z
m×m
q .
b) Set a matrix B
ID
d,i = Ad,i(R
ID
d,i )
−1. Then, run
BasisDel(Ad,i, R
ID
d,i , TAd,i , σ) to generate TB
ID
d,i
∈
Z
m×m
q .
2) ∀ai ∈ Ud − U
ID
d :
a) Randomly choose a matrix B
ID
d,i ∈ Z
n×m
q .
3) Set P Kd = P Kd ∪ {B
ID
d,i }ai∈Ud .
4) Send partial private key SK
ID
d = {TB
ID
d,i
}ai∈U
ID
d
to ID.
5) If ID /
∈ L, set L = L ∪ ID.
ID sets its fully private key SKID = {SK
ID
d }d∈D.
D. Revoke
(B
ID
d,t )
′
← Revoke(GP, P Kd, ID, t): The revocation of the
attribute is executed by AAd involving the target attribute t
and the user’s identity ID. AAd revokes the target attribute
by doing the steps below:
1) Randomly choose a matrix (B
ID
d,t )
′
∈ Z
n×m
q .
2) Replace B
ID
d,t with (B
ID
d,t )
′
.
E. Extend
(P Kd, SK
′
d) ← Extend(GP, P Kd, M Kd, ID, t, SK
ID
d ):
The extension of the attribute is executed by AAd involving
the target attribute t and the user’s identity ID. AAd generates
a new private key of the target attribute for ID by doing the
steps below:
1) Invoke SampleR(1
m) to sample an invertible matrix
R
ID
d,t ∈ Z
m×m
q .
2) Set a matrix (B
ID
d,t )
′
= Ad,t(R
ID
d,t )
−1. Then, run
BasisDel(Ad,t, R
ID
d,t , TAd,t , σ) to generate T(B
ID
d,t )
′ ∈
Z
m×m
q .
3) Replace B
ID
d,t with (B
ID
d,t )
′
.
4) Send partial private key (SK
ID
d )
′
= SK
ID
d ∪ {T(B
ID
d,t )
′ }
to ID.
ID updates its private key SKID = SKID ∪ (SK
ID
d )
′
.
Note: The Enroll, Revoke, and Extend algorithms collec-
tively enable dynamic membership management.
F. Encrypt
CT ← Encrypt(GP, b, k0, W, τ, {P Kd}d∈DC ): DO en-
crypts the message b ∈ {0, 1} with a selected access tree
τ through the steps below:
1) Randomly select a noise value x ∈ χ.
2) Select a combination of operation gates and a set of
attributes UC = {ai}ai∈τ according to the access tree
τ .
3) For each attribute ai ∈ UC, randomly choose a noise
vector x1,d,i ∈ χ
m.
4) Randomly select a value r ∈ Zq and a vector s1 ∈ Z
n
q
and compute
C = u
T s1 · r + b⌊
q
2
⌋ + x ∈ Zq. (1)
5) The value of the root node in the access tree τ is assigned
as r. Then, beginning from the root node, each leaf node
is assigned a value ri according to the operation gate in
τ following the method defined in Section II-B.
6) For each attribute ai ∈ UC and each ID ∈ L, compute
the partial ciphertext as follows:
C
ID
d,i = (B
ID
d,i )
T s1 · ri + x1,d,i ∈ Z
m
q . (2)
7) Select a category of the keyword set k0 ∈ {0, 1}, and
compute K = H0(k0) ∈ Z
n×m
q .
8) Select a keyword set W = {k1, k2, . . . , kj}, where each
ki ∈ {0, 1}
∗ and the last bit of each ki = k0.
9) Generate a binary vector w = (w1, w2, . . . , wl) for W
using k hash functions of the bloom filter BF (l, k)
defined in Section II-C, where each wi ∈ {0, 1}.
10) Randomly select a noise xl ∈ χ, noise vectors x2,d,i ∈
χ
m and a vector s2 ∈ Z
n
q . For θ = 1 to l, compute
I1,θ = u
T s2 · r + wθ⌊
q
2
⌋ + xl ∈ Zq. (3)
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.


===== [ Page 4 ] =====

TABLE II: The Properties Comparison
Multi- Multi- Authentication Collusion KGC/Authorities
Authority Keyword Search Decrypt Resistance Offline
Yang et al. [16]
Sun et al. [17]
Zhuang et al. [18]
Varri et al. [19]
Wang et al. [20]
Li et al. [21]
Chen [22]
Wang [23]
Ours
indicates that the scheme provides the property.
indicates that the scheme does not provide the property.
\ indicates that the application scenario of the scheme does not consider searchable encryption,
so the property is not needed.
11) For each attribute ai ∈ UC and each ID ∈ L, compute
I
ID
d,i = [B
ID
d,i |K]
T s2 · ri + x2,d,i ∈ Z
2m
q . (4)
12) Set the index I
ID = {{I1,θ}1≤θ≤l, {I
ID
d,i }ai∈UC }.
13) Set the ciphertext CT = {C, {C
ID
d,i }ai∈UC ,ID∈L}.
14) Upload (CT, {I
ID}ID∈L, τ ) to CS.
Note: Each ID has independent keys, ensuring collusion
resistance. Both messages and keywords are encrypted, so user
attributes are verified during decryption and search.
G. TokenGen
(w
′
, {k
ID
d,i }ai∈U ID ) ← TokenGen(GP, k
′
0, W
′
,
{P Kd}d∈DC , SKID): DU generate the search token as
follows:
1) Select a category of the keyword set k
′
0 ∈ {0, 1}, and
compute K
′
= H0(k
′
0) ∈ Z
n×m
q .
2) Select a keyword set W
′ = {k
′
1, k
′
2, . . . , k
′
j}, where each
k
′
i ∈ {0, 1}
∗ and the last bit of each k
′
i = k
′
0.
3) Compute a binary vector w
′
for W
′
using k hash
functions of the bloom filter BF (l, k).
4) For each attribute ai ∈ U
ID, run
SampleLeft(B
ID
d,i , K
′
, TB
ID
d,i
, u, σ) to generate
k
ID
d,i ∈ Z
2m
q , where [B
ID
d,i |K
′
]k
ID
d,i = u and U
ID
presents as the attribute set of user ID.
5) Send (w
′
, {k
ID
d,i }ai∈U ID ) to CS.
Note: Since the DU can independently generate tokens, the
scheme achieves an offline KGC architecture.
H. Search
CT /⊥ ← Search(w
′
, {k
ID
d,i }ai∈U ID , {I
ID}ID∈L, τ ): CS
receives the search token (w
′
, {k
ID
d,i }ai∈U ID ) from DU, and
do the steps below:
1) For θ = 1 to l, compute w
′
θ based on the operation gate
in τ , for example:
• When τ is constructed by only AND gates, compute
w
′
θ = I1,θ −
P
ai∈UC (k
ID
d,i )
T I
ID
d,i .
• When τ is constructed by only OR gates, compute
w
′
θ = I1,θ − (k
ID
d,i )
T I
ID
d,i , where ai ∈ UC.
2) If |w
′
θ − ⌊
q
2 ⌋| < ⌊
q
4 ⌋, output w
′
θ = 1; otherwise, output
w
′
θ = 0.
3) Compute the bitwise-or. If w
′
∪ ¯
w = ¯
w, then the keyword
set W
′ ⊂ W .
4) If w
′
∪ ¯
w = ¯
w, send the corresponding ciphertext CT
to DU. Otherwise, return ⊥.
I. Decrypt
b
′
← Decrypt(CT, GP, {P Kd}d∈DC , SKID): Upon re-
ceiving the ciphertext CT , any user whose attribute set meets
the requirements of τ can decrypt the ciphertext by doing the
steps below:
1) For each attribute ai ∈ UC, run
SamplePre(B
ID
d,i , TB
ID
d,i
, u, σ) to generate e
ID
d,i ∈ Z
m
q ,
where B
ID
d,i e
ID
d,i = u.
2) Compute b
′
based on the operation gate in τ , for example:
• When τ is constructed by only AND gates, compute
b
′
= C −
P
ai∈UC (e
ID
d,i )
T C
ID
d,i .
• When τ is constructed by only OR gates, compute
b
′
= C − (e
ID
d,i )
T C
ID
d,i , where ai ∈ UC.
3) If |b
′
− ⌊
q
2 ⌋| < ⌊
q
4 ⌋, output b
′
= 1; otherwise, output
b
′
= 0.
Note: To adapt the proposed scheme for transmitting multi-
ple bits, the encryption process can generate multiple distinct
ciphertexts C, with each C carrying one bit, while other
components, such as (e
ID
d,i )
T and C
ID
d,i , can be reused.
IV. COMPARISONS
We compare the proposed scheme with the post-quantum
searchable encryption schemes in [19]–[23]. Unlike these
schemes, our design supports a multi-authority setting with
independent key pairs, dynamic membership via Enroll,
Revoke, and Extend, offline token generation to reduce
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.


===== [ Page 5 ] =====

TABLE III: Comparison Parameters
Description Value
n Security parameter 284
m Basis dimension 13, 812
q Modulo 2
24
l Size of attribute set UC 10
l
′
Number of bits of a set used in subset predicate encryption (SPE) 10
u Total number of users 50
w Total number of keywords in CT 5
h Total number of hash functions 3
k Length of bloom filter array 32
TABLE IV: Ciphertext, Index, and Token Length
Ciphertext Index Token
Varri et al. [19] (l + n)|Zq| (l + 2mw)|Zq| (2mw + 2lmn)|Zq|
Wang et al. [20] (l
′m + m + 1)|Zq| (l
′m + m)|Zq| 2hm|Zq|
Li et al. [21] 2|Rq| + n|Zq| (w + 1)|Rq| + n|Zq| |Rq|
Chen [22] (lmu + 1)|Zq| (lmu + 1)|Zq| hlm|Zq|
Wang [23] (lmu + 1)|Zq| (lmu + h + w)|Zq| hlm|Zq|
Ours (lmu + 1)|Zq| (2lmu + k)|Zq| 2lm|Zq|
TABLE V: The Notations and Operations Cost
Notation The computation time of Cost
Tmul1 (Zq × Zq) 0.0012(ms)
Tmul2 (Zq × Z
m
q ) 0.0015(ms)
Tmul3 (Z
n
q × Z
n
q ) 0.002(ms)
Tmul4 (Z
1×n
q × Z
n×1
q ) 0.003(ms)
Tmul5 (Z
1×m
q × Z
m×1
q ) 0.012(ms)
Tmul6 (Z
n×2m
q × Z
2m×1
q ) 6.284(ms)
Tmul7 (Z
m×n
q × Z
n×1
q ) 3.077(ms)
Tmul8 (Z
1×2m
q × Z
2m×1
q ) 0.018(ms)
Tmul9 (Zq × Z
2m
q ) 0.273(ms)
Tmul10 (Z
2m×n
q × Z
n×1
q ) 6.101(ms)
TmulR (Rq × Rq) 0.952(ms)
TH SHA-512 for inputs 128 bits 0.016(ms)
TABLE VI: Computation Cost of Encryption
Encryption Searching Decryption
[19]
w ∗ (Tmul4 + TH ) Tmul1 + Tmul3 + 2 ∗ Tmul6 Tmul3 + Tmul6
≈ 0.095(ms) ≈ 12.5712(ms) ≈ 6.286(ms)
[20]
(l
′
∗ w + 1) ∗ Tmul4 + (l
′
+ 1) ∗ Tmul7 + (l
′
∗ w) ∗ TH l
′
∗ Tmul8 Tmul8
≈ 34.8(ms) ≈ 0.18(ms) ≈ 0.018(ms)
[21]
(3 + w) ∗ TmulR + l ∗ TH TmulR + TH TmulR + l ∗ TH
≈ 9.568(ms) ≈ 1.096(ms) ≈ 1.24(ms)
[22]
(2 ∗ u) ∗ (Tmul1 + Tmul4) + (2 ∗ l ∗ u) ∗ Tmul7 + h ∗ TH (h ∗ l) ∗ Tmul5 (2 ∗ l) ∗ Tmul5
≈ 3077.468(ms) ≈ 0.36(ms) ≈ 0.24(ms)
[23]
(2 ∗ l ∗ u) ∗ (Tmul1 + Tmul4 + Tmul7) + h ∗ (Tmul1 + Tmul4 + TH )+ (2 ∗ h) ∗ (l ∗ Tmul2 + Tmul4) (2 ∗ l) ∗ Tmul5
w ∗ TH ≈ 3081.3406(ms) ≈ 0.108(ms) ≈ 0.24(ms)
Ours
(w ∗ h + 1) ∗ TH + 2 ∗ (Tmul1 + Tmul4) + (l ∗ u) ∗ (Tmul2 + Tmul7)+ l ∗ Tmul8 l ∗ Tmul5
(l ∗ u) ∗ (Tmul9 + Tmul10) ≈ 4741.296(ms) ≈ 0.18(ms) ≈ 0.12(ms)
overhead, and collusion resistance through identity-specific
keys and dual encryption on messages and keywords. Table II
summarizes their properties. The parameter settings for com-
parison are provided in Table III.
A. Transmission Cost
Table IV compares ciphertext, index, and token lengths. Let
UC be the set of attributes in the ciphertext (|UC| = l), u
the total number of users, w the number of keywords, h the
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.


===== [ Page 6 ] =====

number of hash functions, and k the bloom filter array length.
Chen’s [22], Wang’s [23], and our scheme multiply ciphertext
size by u, increasing storage but preventing user collusion,
unlike other schemes.
B. Computation Cost
Table V and Table VI show computation costs for en-
cryption, search, and decryption, measured on a Windows
11 Home system (Intel i7-9750H, 8GB RAM, Python 3.9.5,
Numpy 1.20.3). Encryption in Chen’s [22], Wang’s [23], and
our scheme scales with u, increasing time (up to 4741.29
ms) but strengthening security and enabling dynamic mem-
bership. Search and decryption remain efficient, with our
scheme achieving the shortest decryption time among schemes
supporting multi-keyword search. Additionally, while some
schemes require KGC assistance for token generation, ours
and Wang et al. [20], Chen [22], and Wang [23] support offline
KGC, enhancing flexibility. Overall, our scheme balances
richer functionality with practical performance.
V. CONCLUSIONS
In this study, we propose a lattice-based ABE scheme
supporting multi-authority architecture, multi-keyword search,
and dynamic membership management, achieving post-
quantum security under the D-LWE assumption. By decentral-
izing authority across multiple key generators, the scheme mit-
igates key escrow, enhances trust, and resists collusion. Multi-
keyword search improves query flexibility, while attribute
independence and revocation enable fine-grained, dynamic
access control. Although encryption incurs higher overhead,
search and decryption remain efficient and practical. Formal
security guarantees under IND-CPA and IND-CKA models are
provided, with full proofs available upon request.
ACKNOWLEDGMENT
This work was partially supported by the National Science
and Technology Council (NSTC) of Taiwan under grant 114-
2221-E-110-040. It also was supported by the MediaTek Ad-
vanced Research Center under the research contract MTKC-
2024-1133. Additional financial support was provided by the
Information Security Research Center at National Sun Yat-sen
University in Taiwan.
REFERENCES
[1] D. X. Song, D. Wagner, and A. Perrig, “Practical techniques for searches
on encrypted data,” in Proceeding 2000 IEEE symposium on security
and privacy. S&P 2000. IEEE, 2000, pp. 44–55.
[2] D. Boneh, G. Di Crescenzo, R. Ostrovsky, and G. Persiano, “Public
key encryption with keyword search,” in Advances in Cryptology-
EUROCRYPT 2004: International Conference on the Theory and Appli-
cations of Cryptographic Techniques, Interlaken, Switzerland, May 2-6,
2004. Proceedings 23. Springer, 2004, pp. 506–522.
[3] A. Sahai and B. Waters, “Fuzzy identity-based encryption,” in Advances
in Cryptology–EUROCRYPT 2005: 24th Annual International Confer-
ence on the Theory and Applications of Cryptographic Techniques,
Aarhus, Denmark, May 22-26, 2005. Proceedings 24. Springer, 2005,
pp. 457–473.
[4] V. Goyal, O. Pandey, A. Sahai, and B. Waters, “Attribute-based encryp-
tion for fine-grained access control of encrypted data,” in Proceedings
of the 13th ACM conference on Computer and communications security,
2006, pp. 89–98.
[5] J. Bethencourt, A. Sahai, and B. Waters, “Ciphertext-policy attribute-
based encryption,” in 2007 IEEE symposium on security and privacy
(SP’07). IEEE, 2007, pp. 321–334.
[6] C.-I. Fan, V. S.-M. Huang, and H.-M. Ruan, “Arbitrary-state attribute-
based encryption with dynamic membership,” IEEE Transactions on
Computers, vol. 63, no. 8, pp. 1951–1961, 2013.
[7] M. Chase, “Multi-authority attribute based encryption,” in Theory of
Cryptography: 4th Theory of Cryptography Conference, TCC 2007,
Amsterdam, The Netherlands, February 21-24, 2007. Proceedings 4.
Springer, 2007, pp. 515–534.
[8] H. Lin, Z. Cao, X. Liang, and J. Shao, “Secure Threshold Multi
Authority Attribute Based Encryption without a Central Authority,”
Progress in Cryptology–INDOCRYPT 2008, p. 426, 2008.
[9] A. Lewko and B. Waters, “Decentralizing attribute-based encryption,” in
Advances in Cryptology–EUROCRYPT 2011: 30th Annual International
Conference on the Theory and Applications of Cryptographic Tech-
niques, Tallinn, Estonia, May 15-19, 2011. Proceedings 30. Springer,
2011, pp. 568–588.
[10] P. W. Shor, “Algorithms for quantum computation: discrete logarithms
and factoring,” in Proceedings 35th annual symposium on foundations
of computer science. Ieee, 1994, pp. 124–134.
[11] S. Agrawal, X. Boyen, V. Vaikuntanathan, P. Voulgaris, and H. Wee,
“Fuzzy identity based encryption from lattices,” Cryptology ePrint
Archive, 2011.
[12] J. Zhang and Z. Zhang, “A ciphertext policy attribute-based encryption
scheme without pairings,” in Proceedings of the 7th international
conference on Information Security and Cryptology, 2011, pp. 324–340.
[13] X. Boyen, “Attribute-based functional encryption on lattices,” in Theory
of Cryptography: 10th Theory of Cryptography Conference, TCC 2013,
Tokyo, Japan, March 3-6, 2013. Proceedings. Springer, 2013, pp. 122–
142.
[14] L. Liu, S. Wang, B. He, and D. Zhang, “A keyword-searchable ABE
scheme from lattice in cloud storage environment,” Ieee Access, vol. 7,
pp. 109 038–109 053, 2019.
[15] D. Micciancio and C. Peikert, “Trapdoors for Lattices: Simpler, Tighter,
Faster, Smaller.” in Eurocrypt, vol. 7237. Springer, 2012, pp. 700–718.
[16] Y. Yang, J. Sun, Z. Liu, and Y. Qiao, “Practical revocable and multi-
authority CP-ABE scheme from RLWE for Cloud Computing,” Journal
of Information Security and Applications, vol. 65, p. 103108, 2022.
[17] J. Sun, Y. Qiao, Z. Liu, Y. Chen, and Y. Yang, “Practical Multi-
Authority Ciphertext Policy Attribute-Based Encryption from R-
LWE,” in 2021 IEEE Intl Conf on Parallel & Distributed Pro-
cessing with Applications, Big Data & Cloud Computing, Sustain-
able Computing & Communications, Social Computing & Networking
(ISPA/BDCloud/SocialCom/SustainCom). IEEE, 2021, pp. 1435–1443.
[18] E.-S. Zhuang, C.-I. Fan, and I.-H. Kuo, “Multiauthority Attribute-Based
Encryption With Dynamic Membership From Lattices,” IEEE Access,
vol. 10, pp. 58 254–58 267, 2022.
[19] U. S. Varri, S. K. Pasupuleti, and K. Kadambari, “CP-ABSEL:
Ciphertext-policy attribute-based searchable encryption from lattice in
cloud storage,” Peer-to-Peer Networking and Applications, vol. 14, pp.
1290–1302, 2021.
[20] P. Wang, B. Chen, T. Xiang, and Z. Wang, “Lattice-based public
key searchable encryption with fine-grained access control for edge
computing,” Future Generation Computer Systems, vol. 127, pp. 373–
383, 2022.
[21] C. Li, M. Dong, J. Li, G. Xu, X.-B. Chen, W. Liu, and K. Ota, “Efficient
medical big data management with keyword-searchable encryption in
healthchain,” IEEE Systems Journal, vol. 16, no. 4, pp. 5521–5532,
2022.
[22] X.-J. Chen, “Lattice-Based Searchable Attribute-Based Encryption Sup-
porting Dynamic Membership Management,” Master thesis, National
Sun Yet-sen University, 2021.
[23] D.-R. Wang, “Multi-Keyword Searchable Attribute-Based Encryption
Supporting Dynamic Membership Management from Lattices,” Master
thesis, National Sun Yet-sen University, 2022.
Authorized licensed use limited to: Thammasat University. Downloaded on August 02,2026 at 10:15:43 UTC from IEEE Xplore. Restrictions apply.

