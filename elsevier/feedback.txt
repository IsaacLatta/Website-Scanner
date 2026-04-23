Thank you authors for the submission. The three experts who reviewed this paper agree that the paper has an interesting question, suitable for COSE's scope, and of interest of COSE's audience. However, all experts also point crucial issues that must be addressed to take the paper to a publishable state. I recommend the authors to carefully address these issues in a Major Revision.

---------- Reviewer's Comments -------------

Reviewer #1: I read this paper with interest. The question it asks - whether Canada's advisory-only approach to web security produces worse outcomes than the mandate-driven models in the US and UK - is a good one, and one that hasn't really been addressed in the literature for Canada specifically. The decision to separate origin-scoped measurements (TLS, HSTS) from endpoint-scoped ones (headers, cookies) is sound and I think it adds genuine methodological value. The open-sourcing of the scanner and datasets is appreciated.

That said, I have a number of concerns, some of them fairly serious, that I think need to be addressed before this is ready for publication.

1. UK Authority Comparison
This is probably the biggest issue. Table 2 shows that 348 UK authority input URIs collapsed to just 4 unique origins because everything routes through GOV.UK. So when Tables 4-10 report things like "100% TLS 1.3" or "100% Preload" for UK authorities, that's really telling us about how one platform team configured a handful of servers. It doesn't tell us anything about whether a mandate-driven policy environment causes individual organizations to adopt better configurations. I don't think you can use this dataset for the governance argument the paper is trying to make. The UK numbers conflate IT centralization with the effect of mandates. If you want to keep the UK data in the paper, I'd suggest presenting it separately as a case study in what centralized hosting can achieve, but pulling it out of the formal cross-jurisdiction comparisons. The US authority dataset (n=373) is a much better comparator.

2. Statistical Treatment
There are no confidence intervals, no significance tests, nothing. Every comparison in the paper is just raw percentages. When you write that Canadian authorities "underperform" US authorities on HSTS (59.73% vs 89.74%), that's probably a real difference given the sample sizes, but you haven't actually shown that. And some of your other comparisons involve much smaller groups (US education n=53, UK authorities n=4) where I'm genuinely not sure if the differences hold up. At a minimum I'd want to see Wilson confidence intervals on the proportions and some form of test (Fisher's exact or chi-square) for the cross-group claims. I realize this is a measurement paper, not an experiment, but if you're going to assert that one population performs worse than another, you need to back that up.

3. CSP Analysis
I understand the decision to scope the CSP analysis to frame-ancestors. The issue is more about how the findings get framed afterward. When the paper uses CSP adoption rates to argue about "defense-in-depth gaps" and describes CSP as a "modern browser policy control," a reader could reasonably conclude that the 17.9% of Canadian authority endpoints deploying CSP are getting broad content-injection defense. But the analysis only measured framing protection, not XSS protection. A site with a CSP full of unsafe-inline and wildcard script sources would pass this test. I think the fix is just to qualify the claims more carefully. You can it make clear that CSP is being measured as a framing control here, not as an XSS mitigation. If you wanted to go further, you have the raw CSP header strings in your dataset and could report unsafe-inline/unsafe-eval prevalence without rescanning, but that's your call.

4. TLS Cipher Suite Data
Section 4.2 says it will report "(iii) (where measured) TLS 1.2 cipher-suite quality" but this data doesn't appear anywhere in the paper. I looked at your public repository and can see that you did collect cipher suite data. It's your call what results to present, but the text makes a specific promise to the reader and then doesn't follow through. Either include the data or remove the claim from Section 4.2 so expectations match what's delivered.

5. Governance Framing
The paper characterizes Canada as operating under a purely "recommendation-driven" model, contrasting it with US and UK mandates. But the Treasury Board Secretariat issues directives (e.g., the Directive on Service and Digital) that are binding on federal departments. CCCS guidance is advisory, yes, but TBS policy is not. This distinction matters quite a bit for your central argument. I'd suggest distinguishing between federal departments and provincial entities (where CCCS guidance really is just advisory) rather than treating all Canadian authorities as operating under the same governance model. Related to this: have you considered looking at whether federal vs. provincial origins show different adoption patterns within your Canadian authority dataset? That would actually let you test, at least preliminarily, whether the governance mechanism you're proposing has explanatory power within a single jurisdiction.

6. Threat Modeling
The paper treats all missing headers as roughly equivalent failures, but that doesn't really hold up. Missing HSTS on a site that handles tax filings is a different risk than a missing Permissions-Policy on a static informational page that doesn't use the camera or microphone. Some acknowledgment that the severity of a missing control depends on the site's functionality would strengthen the analysis. As it stands, reporting that only 8.6% of authority endpoints deploy Permissions-Policy is technically accurate, but what does it actually mean for the risk profile of a site that doesn't use any of the restricted APIs?

7. Ethical Disclosures
The 404 probes extracted version information from about 10.7% of Canadian authority origins. The ethics statement describes the scanning methodology as non-invasive, and I accept that it is, but did you communicate these version-leak findings to any of the affected operators or to CCCS? The paper doesn't say. I also couldn't find any mention of whether you sought institutional ethics review (REB) for this work.

8. Lit Review
The related work section leans heavily on practitioner documentation (OWASP, MDN) and doesn't engage much with the academic measurement literature. There's a substantial body of work on large-scale web scanning (Durumeric et al. on Censys/ZMap), HTTPS adoption measurement (Felt et al.), and HTTP security header deployment (Van Goethem et al.) that you should be positioning your study against. The DHS Cyber Hygiene reports and the UK NCSC's Active Cyber Defence annual reports would also give you published longitudinal baselines for the jurisdictions you're comparing to.

MINOR POINTS
* The paper doesn't state when the scans were actually conducted. Please add exact dates.
* Table 5 labels the preload column as "Preload (%)" but you're measuring preload "signaling" in the header, not actual inclusion in browser preload lists. The column header should reflect that.
* Section 4.1 spends a lot of space discussing what "unreachable" might mean. I'd tighten that up.
* The key findings get restated in the abstract, intro, Section 4.6, Section 5.1, and the conclusion. That's at least two times too many.


Reviewer #2: The challenges raised by the continuous digitalization of public services represent a relevant research topic that has been attracting the attention and efforts of multiple research teams worldwide. This manuscript focuses on the Canadian case, with particular attention to the information security of public-facing web services. Although the results are interesting, the work appears somewhat limited to a national context, which may constrain its international impact and reach. Recent works have been addressing the same topic from a global perspective (e.g., D Ribeiro, V Fonte, LF Ramos, JM Silva. Assessing the information security posture of online public services worldwide: Technical insights, trends, and policy implications. In: Government Information Quarterly, 2025) and are not considered along the submmited manuscript. This does not mean the work is without merit, but it should be substantially enhanced before being published in a top-tier venue such as Computers & Security.

The following points are intended to guide the improvement of the manuscript:

- The authors claim to have "developed and validated a multi-layer evaluation methodology," which is an overstatement. While a tool has indeed been developed and made publicly available, the assessment methods employed are widely used across different services and platforms (e.g., Mozilla HTTP Observatory, nmap, and Cookie Scanner), and do not constitute a novel methodology. The authors should revise this claim accordingly. Additionally, the rationale for comparing the Canadian landscape with British and North American contexts is not clearly justified and should be explicitly articulated.
- The evaluation of TLS/HTTPS connections is incomplete without inspecting digital certificate chains. Since the TLS protocol ensures not only the encryption of the communication channel but also server authenticity, this dimension is mandatory and should be incorporated into the analysis. Issues related to digital certificate management in the public sector have been reported in the literature and can be included while preserving the non-intrusive nature of the assessment. Furthermore, for older TLS versions that may remain active for backward compatibility reasons, support for weak or insecure cipher suites should also be considered in this analysis.
- The manuscript adopts classification schemes that are not adequately explained. For instance, cookie posture is evaluated as "recommended," "sufficient," or "insufficient," yet no reasoning is provided to justify these categories. The same issue applies to the HSTS assessment. Given the low percentage of sites using cookies, it is also important to characterize the types of cookies observed, as not all cookies represent a security risk, yet the authors appear to treat them as such.
- There is considerable content repetition between the Results and Methodology sections, which should be addressed.
- The size of the analyzed dataset also requires clarification: the authors state they assessed 375 unique Canadian authority websites, but Table 2 indicates that connections were established with only 68% of them. The total number of websites effectively evaluated in this study must be unambiguously stated.
- The conclusion that regulated sectors are more compliant with a secure web posture is difficult to follow. For example, Tables 5 and 6 show similar results between CA Authorities and CA Energy websites, which does not straightforwardly support this claim. Some statements appear to describe a situation worse than what the data actually reflect. More broadly, certain conclusions lack support from the study as described. For instance, the assertion that "results suggest that many gaps in Canadian public-sector web posture are not driven by a lack of technical capacity, but by inconsistent operationalization of well-known configuration practices" is not substantiated by the presented analysis.
- Some passages are difficult to follow and require revision. For example, the statement "cross-jurisdiction comparisons reinforce the hypothesis that governance environments shape observable deployment" is unclear, the origin of this hypothesis is not established, and its precise meaning is ambiguous. The authors should also include recent references from the literature on public-sector security posture assessment and situate their findings within the broader global landscape.


Reviewer #3: ##SUMMARY##

The paper presents a standards-aligned, non-invasive measurement study
of web security configuration across 375 Canadian public-sector
authority origins, benchmarked against domestic critical sectors
(finance, education, energy) and international peers (US, UK). It
addresses the research question of whether implementing
recommendations through a governance model yields equivalent
security-configuration deployment outcomes as in mandate-driven
environments. This is both timely and well-motivated. The main
methodological contribution of this work is the identification and
separate measurement of origin-scoped transport controls (enforcement
of HTTPS, TLS posture and HSTS configuration) vs. endpoint-scoped
browser enforced policies (e.g., security header and cookie
attributes), using a modular non-invasive scanner. The scanner
implementation is publicly available. The structure of the paper is
logical and the results obtained are presented in a systematic manner.
Despite this, two major issues and six minor issues have been
identified and need to be addressed before this paper can be accepted
for publication in Computers & Security.

##MAJOR ISSUES##

1. Only 4 distinct final origins result from the aggregation of 349
individual UK authority URIs (Table 2), all of which are 100%
reachable via HTTPS (Table 3). This compression is the effect of
centralization within the UK government hosting infrastructure
(GOV.UK) rather than an indicator of the individual security
configurations of member agencies. As currently presented, the UK
authority statistics (e.g., 100% TLS 1.3 negotiation rate and 87.6%
CSP frame-ancestors adoption in Table 6) are treated throughout the
paper as indicative of mandate-driven governance effectiveness, when
in fact they characterize only 4 shared hosting endpoints. Thus,
direct comparisons with the Canadian authority dataset (n = 375
origins) may not be fully warranted. To rectify this, either the UK
authorities should be excluded from cross-jurisdiction analyses and
replaced with a comparison between Canada and the United States, or a
clear, prominent disclaimer should be added in the relevant sections
of the text (including the discussion and conclusions). The paper, as
currently drafted, can mislead readers into making governance-level
observations based on an infrastructure-level artifact.

2. The central comparative statements made by the paper involve
observed differences in proportions between sectors and countries
(e.g., Canadian authorities having an HSTS adoption of 59.73% versus
89.74% in US authorities). The paper presents these as descriptive
statistics of a population, however, it offers no confidence
intervals, or other formal statistical tests to substantiate that the
differences observed in the data are actually statistically
significant and not merely due to the sizes of the samples in
question. The paper should include confidence intervals for the most
significant proportions detailed in Tables 3 through 10. Furthermore,
the prominent comparisons between groups should be accompanied by
statistical significance tests to support the claims made in the
discussion and conclusion sections.

##MINOR ISSUES##

3. ``Lattia'' is stated as the first author's surname on the cover
abstract page, as the first author on the title page and throughout
the body of the manuscript. The authors' CRediT contribution statement
(Section 7) and the GitHub reference (Latta and Keshvadi, 2026) cite
``Latta'' as the surname. The author's surname should be standardized
to ensure consistency across all parts of the manuscript, including
indexing, discoverability and citation. If ``Latta'' is the correct
surname, then ``Lattia'' must be consistently replaced with ``Latta''.

4. The entry for Dunbar in the bibliography provides only a working
paper number (SSRN 4240917) and a partial title, with no year of
publication, journal name, volume, or page number. This needs to be
amended into a complete bibliographic reference according to the
journal's formatting standards. I believe the citation should be
based on:

Dunbar, De'Jean, Survey of United States Related Domains: Secure
Network Protocol Analysis (Septemeber 16, 2022).
https://aircconline.com/abstract/ijnsa/v14n5/14522ijnsa03.html,
Available at SSRN: https://ssrn.com/abstract=4240917

5. The strategy for sampling US finance and education institutions
involves selecting institutions from the ten states with the largest
populations, using those population statistics to determine
eligibility. This selection method could inherently favor states with
higher economic output and tech sectors, thus leading to a biased US
baseline in the study, compared with a nationally representative
sample of US authorities. The paper would benefit from discussing
alternative sampling strategies considered and assessing whether the
results vary based on such a choice. A brief mention of this potential
bias and its likely direction in the methodology or limitations
sections would improve the paper.

6. Although the paper specifies the data scanning originating from a
Google Cloud Platform server in us-central1 and notes that the scanner
records timestamps (Section 3.4), the exact dates for the measurement
campaign weren't disclosed. For a cross-sectional study that surveys
web configuration posture, the scan start and end dates should be
explicitly specified, so readers can place the results in context,
such as relative to governance changes, platform migrations, or
security incidents that have happened during or since the scan period.

7. In Canadian Finance, the Secure flag is only associated with 32.2%
of cookie-setting endpoints in Table 7, compared with an HttpOnly flag
presence of 83.3%. Typically, the Secure flag is considered the more
crucial aspect of session security. A scenario in which HttpOnly flags
significantly exceed Secure flags for cookie-setting endpoints is
atypical and merits an explanation. The authors should examine whether
this unusual trend results from mixed HTTP and HTTPS endpoints, a high
presence of non-sensitive analytics cookies, or another operational
issue and include a short interpretive statement regarding this
finding in Section 4.4.

8. The paper notes the extremely low adoption of the Referrer-Policy
header (17.4% in Canadian authorities, Table 6) but provides less
detailed coverage of its implications than other header
directives. Because the Referrer-Policy can prevent the transmission
of sensitive URL parameters (e.g., session IDs passed in URLs) to
external websites, its limited adoption is functionally relevant to
the discussion of information governance in Section 4.5. A short
connecting sentence would improve the thematic link between Sections
4.3 and 4.5.
