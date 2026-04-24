## Reviewer #1

### Comment 1

> "**UK Authority Comparison**
> This is probably the biggest issue. Table 2 shows that 348 UK authority input URIs collapsed to just 4 unique origins because everything routes through GOV.UK. So when Tables 4-10 report things like ‘100% TLS 1.3’ or ‘100% Preload’ for UK authorities, that's really telling us about how one platform team configured a handful of servers. It doesn't tell us anything about whether a mandate-driven policy environment causes individual organizations to adopt better configurations. I don't think you can use this dataset for the governance argument the paper is trying to make. The UK numbers conflate IT centralization with the effect of mandates. If you want to keep the UK data in the paper, I'd suggest presenting it separately as a case study in what centralized hosting can achieve, but pulling it out of the formal cross-jurisdiction comparisons. The US authority dataset (n=373) is a much better comparator." 

**Changes made**

* Revised the manuscript to remove UK authorities from the main governance comparison.
* Reframed the **Canada–U.S. authority comparison** as the principal public-sector comparator.
* Retained UK authority results only as **descriptive context** / a **centralized-hosting case**, not as organization-level evidence of mandate effectiveness.
* Added explicit disclaimer language in the **Introduction**, **Methodology**, **Results**, **Discussion**, and **Conclusion** stating that UK authority results are strongly shaped by centralized GOV.UK hosting.
* Excluded UK authorities from the inferential comparison summary table.

---

### Comment 2

> "**Statistical Treatment**
> There are no confidence intervals, no significance tests, nothing. Every comparison in the paper is just raw percentages. When you write that Canadian authorities ‘underperform’ US authorities on HSTS (59.73% vs 89.74%), that's probably a real difference given the sample sizes, but you haven't actually shown that. And some of your other comparisons involve much smaller groups (US education n=53, UK authorities n=4) where I'm genuinely not sure if the differences hold up. At a minimum I'd want to see Wilson confidence intervals on the proportions and some form of test (Fisher's exact or chi-square) for the cross-group claims. I realize this is a measurement paper, not an experiment, but if you're going to assert that one population performs worse than another, you need to back that up." 

**Changes made**

* Added a new summary table reporting **Wilson 95% confidence intervals** and **formal two-group tests** for the manuscript’s principal comparative claims.
* Used **Fisher’s exact test** for sparse comparisons and **chi-square tests of independence** otherwise.
* Revised the discussion and conclusion so stronger comparative language is used only for claims supported in the statistical summary.
* Treated unsupported comparisons descriptively rather than inferentially.

---

### Comment 3

> "**CSP Analysis**
> I understand the decision to scope the CSP analysis to frame-ancestors. The issue is more about how the findings get framed afterward. When the paper uses CSP adoption rates to argue about ‘defense-in-depth gaps’ and describes CSP as a ‘modern browser policy control,’ a reader could reasonably conclude that the 17.9% of Canadian authority endpoints deploying CSP are getting broad content-injection defense. But the analysis only measured framing protection, not XSS protection. A site with a CSP full of unsafe-inline and wildcard script sources would pass this test. I think the fix is just to qualify the claims more carefully..." 

**Changes made**

* Clarified in **Methodology** and **Results** that CSP was evaluated only through the presence of the **`frame-ancestors`** directive.
* Revised text so CSP findings are interpreted as evidence about **framing protection / clickjacking control**, not as a general assessment of CSP-based XSS mitigation.
* Added explicit scope-limitation language to avoid implying that measured CSP presence reflects broad content-injection defense.

---

### Comment 4

> "**TLS Cipher Suite Data**
> Section 4.2 says it will report ‘(iii) (where measured) TLS 1.2 cipher-suite quality’ but this data doesn't appear anywhere in the paper. I looked at your public repository and can see that you did collect cipher suite data. It's your call what results to present, but the text makes a specific promise to the reader and then doesn't follow through. Either include the data or remove the claim from Section 4.2 so expectations match what's delivered." 

**Changes made**

* Added explicit limitation language stating that certificate-chain/authenticity analysis and cipher-suite quality are out of scope for the present paper.
* **NOTE**: I forgot to remove the cipher suite recording claim, it can be found with searching for "and, if enabled, negotiated cipher suite". This looks like the only reference now.  

---

### Comment 5

> "**Governance Framing**
> The paper characterizes Canada as operating under a purely ‘recommendation-driven’ model, contrasting it with US and UK mandates. But the Treasury Board Secretariat issues directives (e.g., the Directive on Service and Digital) that are binding on federal departments. CCCS guidance is advisory, yes, but TBS policy is not. This distinction matters quite a bit for your central argument..." 

**Changes made**

* Revised the framing of Canada’s governance environment to avoid describing it as purely recommendation-driven.
* Clarified that Canadian federal organizations operate within a broader Treasury Board digital-policy environment, while the specific web-facing controls studied here appear less explicitly mandated than in the U.S.
* Reframed the central comparison around **public-web control explicitness** rather than a simple binary of "mandate-driven" vs "recommendation-driven."
* Removed UK authorities from the governance argument.

---

### Comment 6

> "**Threat Modeling**
> The paper treats all missing headers as roughly equivalent failures, but that doesn't really hold up. Missing HSTS on a site that handles tax filings is a different risk than a missing Permissions-Policy on a static informational page that doesn't use the camera or microphone. Some acknowledgment that the severity of a missing control depends on the site's functionality would strengthen the analysis..." 

**Changes made**

* Added text clarifying that the practical severity of a missing control depends on site functionality and exposure.
* Clarified that the implications of a missing **Permissions-Policy** differ between interactive services and static informational pages.
* Revised wording so missing controls are not implicitly treated as equally severe across all sites.

---

### Comment 7

> "**Ethical Disclosures**
> The 404 probes extracted version information from about 10.7% of Canadian authority origins. The ethics statement describes the scanning methodology as non-invasive, and I accept that it is, but did you communicate these version-leak findings to any of the affected operators or to CCCS? The paper doesn't say. I also couldn't find any mention of whether you sought institutional ethics review (REB) for this work." 

**Changes made**

* Expanded the ethics statement to clarify that the study used non-invasive, unauthenticated requests against publicly accessible services.
* Added a statement indicating that institutional ethics review was not sought because the study did not involve human participants, personal data collection, or access to private systems.
* Added a statement clarifying that the version-disclosure observations were not individually reported to affected operators or CCCS, because the study was conducted as a broad cross-sectional measurement exercise rather than a coordinated disclosure effort.

---

### Comment 8

> "**Lit Review**
> The related work section leans heavily on practitioner documentation (OWASP, MDN) and doesn't engage much with the academic measurement literature. There's a substantial body of work on large-scale web scanning ... that you should be positioning your study against..." 

* **NOTE**: Did not address this.

---

### Minor point

> "The paper doesn't state when the scans were actually conducted. Please add exact dates." 

**Changes made**

* Added the measurement date and time in the **scan-window** subsection.

### Minor point

> "Table 5 labels the preload column as ‘Preload (%)’ but you're measuring preload ‘signaling’ in the header, not actual inclusion in browser preload lists. The column header should reflect that." 

**Changes made**

* Renamed the HSTS preload column to reflect **preload signaling**, not confirmed preload-list inclusion.

### Minor point

> "Section 4.1 spends a lot of space discussing what ‘unreachable’ might mean. I'd tighten that up." 

**Changes made**

* Tightened the unreachable discussion and reduced speculative detail.

### Minor point

> "The key findings get restated in the abstract, intro, Section 4.6, Section 5.1, and the conclusion. That's at least two times too many." 

* **NOTE**: I did not address this.

---

## Reviewer #2

### Comment

> "The authors claim to have ‘developed and validated a multi-layer evaluation methodology,’ which is an overstatement. While a tool has indeed been developed and made publicly available, the assessment methods employed are widely used across different services and platforms ... and do not constitute a novel methodology. The authors should revise this claim accordingly. Additionally, the rationale for comparing the Canadian landscape with British and North American contexts is not clearly justified and should be explicitly articulated." 

**Changes made**

* Removed or softened language implying methodological novelty.
* Recast the contribution as a **standards-aligned, non-invasive measurement study** implemented through a unified scanner, rather than a newly validated methodology.
* Added explicit rationale in the Introduction for including the U.S. as the principal public-sector comparator and the U.K. as descriptive centralized-hosting context.

---

### Comment

> "The evaluation of TLS/HTTPS connections is incomplete without inspecting digital certificate chains. Since the TLS protocol ensures not only the encryption of the communication channel but also server authenticity, this dimension is mandatory and should be incorporated into the analysis... Furthermore, for older TLS versions ... support for weak or insecure cipher suites should also be considered..." 

**Changes made**

* Narrowed the manuscript’s claims so that TLS findings are clearly presented as **transport-configuration posture**, not a full assessment of authenticity or PKI trust.
* Added explicit limitation language stating that certificate-chain validity, trust-anchor correctness, hostname verification, and related authenticity checks were not evaluated.
* Added future-work language identifying certificate-chain validation and optional cipher-suite analysis as possible extensions.
* **NOTE**: I forgot to remove the cipher suite recording claim, it can be found with searching for "and, if enabled, negotiated cipher suite". This looks like the only reference now.   

---

### Comment

> "The manuscript adopts classification schemes that are not adequately explained. For instance, cookie posture is evaluated as ‘recommended,’ ‘sufficient,’ or ‘insufficient,’ yet no reasoning is provided to justify these categories. The same issue applies to the HSTS assessment. Given the low percentage of sites using cookies, it is also important to characterize the types of cookies observed..." 

**Changes made**

* Added explicit explanation of the cookie classification scheme in the Methods section.
* Clarified that the categories are a **practical baseline hardening operationalization** derived from CCCS and MDN guidance, not a formal external taxonomy.
* Clarified that cookies are analyzed only on the public landing response and that the results reflect baseline hygiene rather than a full session audit.
* Added interpretive language noting that landing-page cookies may include heterogeneous operational, consent, telemetry, routing, or legacy cookies, and therefore not all observed cookies necessarily represent authentication or high-risk session state.

---

### Comment

> "There is considerable content repetition between the Results and Methodology sections, which should be addressed." 

* **NOTE**: Did not address this.

---

### Comment

> "The size of the analyzed dataset also requires clarification: the authors state they assessed 375 unique Canadian authority websites, but Table 2 indicates that connections were established with only 68% of them. The total number of websites effectively evaluated in this study must be unambiguously stated." 

**Changes made**

* Clarified that different modules use different effective measured sets.
* Stated explicitly that **origin-scoped** analyses use the deduplicated **unique-origin** set and **endpoint-scoped** analyses use the **final resolved-URI** set.
* Clarified that the 68.4% figure in the redirect table refers to the share of input URIs resolving to a final 2xx landing response, not the total origin-scoped denominator for all later tests.

---

### Comment

> "The conclusion that regulated sectors are more compliant with a secure web posture is difficult to follow. For example, Tables 5 and 6 show similar results between CA Authorities and CA Energy websites ... Some statements appear to describe a situation worse than what the data actually reflect..." 

**Changes made**

* Softened broad domestic-sector compliance claims.
* Kept only the strongest, well-supported comparisons in the inferential summary.
* Recast broader domestic-sector observations in more cautious descriptive language where the evidence is mixed.
* Removed or weakened statements that implied more than the presented analysis could support.

---

### Comment

> "Some passages are difficult to follow and require revision. For example, the statement ‘cross-jurisdiction comparisons reinforce the hypothesis that governance environments shape observable deployment’ is unclear ..." 

**Changes made**

* Revised several unclear or overstrong statements, especially around governance interpretation and cross-jurisdiction comparison.
* Simplified wording where the original text overstated the strength or clarity of the inference.

---

### Comment

> "The authors should also include recent references from the literature on public-sector security posture assessment and situate their findings within the broader global landscape." 

**Changes made**

**NOTE**": Did not address this.

---

## Reviewer #3

### Major Issue 1

> "Only 4 distinct final origins result from the aggregation of 349 individual UK authority URIs (Table 2) ... As currently presented, the UK authority statistics ... are treated throughout the paper as indicative of mandate-driven governance effectiveness, when in fact they characterize only 4 shared hosting endpoints. Thus, direct comparisons with the Canadian authority dataset ... may not be fully warranted. To rectify this, either the UK authorities should be excluded from cross-jurisdiction analyses and replaced with a comparison between Canada and the United States, or a clear, prominent disclaimer should be added ..." 

**Changes made**

* Removed UK authorities from the paper’s primary governance comparison.
* Added prominent disclaimer language explaining that the UK authority dataset largely reflects centralized GOV.UK infrastructure rather than independent organization-level deployment.
* Reframed UK authority results as descriptive context / centralized-hosting evidence.
* Excluded UK authority comparisons from the inferential summary table.

---

### Major Issue 2

> "The central comparative statements made by the paper involve observed differences in proportions between sectors and countries ... however, it offers no confidence intervals, or other formal statistical tests to substantiate that the differences observed in the data are actually statistically significant ... The paper should include confidence intervals for the most significant proportions detailed in Tables 3 through 10..." 

**Changes made**

* Added Wilson 95% confidence intervals and formal inferential tests for the manuscript’s principal comparative claims.
* Introduced a statistical-summary table covering the most important Canada–U.S. authority contrasts and selected principal comparisons.
* Revised prose so inferential language is used only where supported by the new summary table.

---

### Minor Issue 3

> " ‘Lattia’ is stated as the first author's surname ... If ‘Latta’ is the correct surname, then ‘Lattia’ must be consistently replaced with ‘Latta’." 

**Changes made**

* Corrected the name.

---

### Minor Issue 4

> "The entry for Dunbar in the bibliography provides only a working paper number ... This needs to be amended into a complete bibliographic reference ..." 

**Changes made**

* Corrected and completed the Dunbar bibliography entry.

---

### Minor Issue 5

> "The strategy for sampling US finance and education institutions involves selecting institutions from the ten states with the largest populations ... This selection method could inherently favor states with higher economic output and tech sectors ... A brief mention of this potential bias and its likely direction in the methodology or limitations sections would improve the paper." 

**Changes made**

* Added a limitations statement acknowledging that sampling U.S. finance and education from the ten most populous states may bias the U.S. baseline toward larger, better-resourced, and potentially more technologically mature institutions.

---

### Minor Issue 6

> "Although the paper specifies the data scanning originating from a Google Cloud Platform server in us-central1 ... the exact dates for the measurement campaign weren't disclosed..." 

**Changes made**

* Added the scan date and time in the scan-window description.

---

### Minor Issue 7

> "In Canadian Finance, the Secure flag is only associated with 32.2% of cookie-setting endpoints ... A scenario in which HttpOnly flags significantly exceed Secure flags ... merits an explanation..." 

**Changes made**

* Added a short interpretive statement in the cookie-results section explaining that the unusually high `HttpOnly`-relative-to-`Secure` pattern may reflect a heterogeneous mix of landing-page operational cookies, legacy compatibility, reverse-proxy/TLS-termination behavior, or framework defaults.

---

### Minor Issue 8

> "The paper notes the extremely low adoption of the Referrer-Policy header (17.4% in Canadian authorities, Table 6) but provides less detailed coverage of its implications ... A short connecting sentence would improve the thematic link between Sections 4.3 and 4.5." 

**Changes made**

* Added a short connecting sentence linking low `Referrer-Policy` adoption to information-governance concerns, especially the possibility of disclosing full referring URLs, paths, or query parameters to external destinations.

---

# Optional closing line for the response letter

> We thank the reviewers for their careful and constructive feedback. In response, we substantially revised the manuscript by reframing the cross-jurisdiction comparison around Canada and the United States, adding inferential support for the principal comparative claims, tightening scope statements to better match what was actually measured, and clarifying limitations, ethics, and interpretation throughout.
