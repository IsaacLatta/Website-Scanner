Reviews:
============== Review #1 ==============

Technical content and correctness: Marginal work and minor contribution. Some flaws
Novelty and originality: Some novel results on a subject well investigated
Clarity and presentation: Generally clear but some parts need improvement
Quality of presentation: Readable
Relevance and timeliness: Average

Strengths :
This paper conducts a large-scale comparative measurement study on the current state of security configurations on Canadian government authority websites. The research topic holds significant practical relevance and provides valuable references for policymakers and technical managers.

Weaknesses:
The current research is more akin to an excellent "health check-up report"; the article lacks sufficient theoretical and technical depth. Its value could be significantly enhanced if it went a step further in terms of attribution analysis and recommendations.

Recommended Changes:
1. The measurement was conducted within a specific time window. Web security configurations are dynamic, and a single snapshot may not reflect long-term trends and could be biased due to transient outages or changes during the measurement period. The study should extend the specific timeframe for data collection.
2. The study mentions measuring "technology leakage in error responses," which typically refers to the exposure of server versions or backend technology stacks in error pages. How was this leakage defined and quantified? Was a distinction made between inadvertent disclosures (such as standard HTTP status codes) and avoidable exposure of sensitive information?


============== Review #2 ==============

Relevance and timeliness: Above average
Technical content and correctness: Solid work of some importance
Novelty and originality: Some novel results on a subject well investigated
Clarity and presentation: Well written and easy to follow
Quality of presentation: Well written

Strengths :
This paper presents a well-executed and methodologically rigorous large-scale measurement study that meaningfully contributes to understanding the security posture of Canadian public-sector web services. A key strength lies in its careful operationalization of CCCS guidance and widely adopted standards (RFCs, OWASP, MDN) into measurable, reproducible benchmarks. The distinction between origin-scoped transport controls and endpoint-scoped browser-enforced protections demonstrates strong technical precision and improves analytical clarity. The dataset is substantial and thoughtfully constructed, drawing from authoritative registries across sectors and jurisdictions. The scanner design is ethically grounded and non-invasive, with validation procedures described in sufficient detail to support reproducibility. The results are clearly presented through structured tables and comparative analysis, and the discussion appropriately contextualizes findings within governance differences between Canada, the U.S., and the U.K. Overall, the paper combines practical relevance, methodological transparency, and policy impact in a compelling way.

Weaknesses:
While the study is methodologically sound, it remains limited to configuration-level measurement and does not evaluate exploitability or real-world attack feasibility. As such, the findings demonstrate exposure rather than confirmed vulnerability. The paper also does not perform statistical significance testing or deeper inferential analysis to quantify the robustness of cross-jurisdiction comparisons. Some datasets—particularly UK Authorities—are small, which may limit the generalizability of certain conclusions. Endpoint evaluation is restricted to final landing pages and does not cover authenticated or transactional paths, which may have different security properties. Additionally, while governance differences are suggested as explanatory factors for observed disparities, the analysis does not empirically test or model these relationships. These limitations do not undermine the study but constrain the depth of causal insight it provides.

Recommended Changes:
If accepted, the paper would benefit from several refinements to strengthen its analytical depth and policy impact. First, incorporating statistical confidence intervals or hypothesis testing would enhance the rigor of cross-country comparisons. Second, clearer discussion of small-sample datasets and their interpretive limitations would improve transparency. Third, expanding the discussion on structural or governance factors influencing deployment quality—possibly supported by supplementary evidence—would deepen the policy contribution. Where feasible, broader endpoint coverage or limited validation of high-risk findings (e.g., error-message leakage patterns) would further strengthen the results. Finally, a short architectural appendix detailing scanner components and processing logic could enhance reproducibility for other researchers seeking to replicate or extend the work.


============== Review #3 ==============

Clarity and presentation: Well written and easy to follow
Quality of presentation: Well written
Technical content and correctness: Solid work of some importance
Novelty and originality: Novel results and original work
Relevance and timeliness: Excellent

Strengths :
The paper addresses an important area of cybersecurity. As a large portion of modern Internet communication relies on web applications, ensuring the security of web-based services, particularly those operated by public-sector organizations, is critical. The study focuses on a relevant and practical problem and contributes useful empirical insights. In addition, the methodology is clearly described and appears to be carefully implemented, which improves the transparency and reproducibility of the work. Overall, the paper presents a well-executed study on a meaningful topic.

Weaknesses:
The primary novelty of the work lies in the domain to which the methodology is applied rather than in the methodology itself, which largely builds on established measurement and scanning techniques. In addition, the datasets used for cross-country and cross-sector comparisons differ significantly in size, which may affect the reliability of direct comparisons. The study also relies mainly on descriptive statistics, and no statistical significance testing is presented to support the observed differences. Nonetheless, the reported results still provide useful insights into the security posture of the evaluated websites.

Recommended Changes:
• Incorporate appropriate statistical tests to support the comparative analysis and demonstrate the significance of the reported differences across datasets.
• Provide a discussion of dataset size imbalance, particularly where cross-country or cross-sector comparisons involve substantially different sample sizes.
• Review and correct formatting issues in the reference section, particularly with URL formatting.
• Verify and update broken links; for example, the URL in Reference #4 appears to no longer resolve.