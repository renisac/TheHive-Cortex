# APWG Cortex Responder
Summary: Submits indicators to APWG from TheHive

Applies To: Case Observables (Artifacts), Alerts

Data sensitivity: This responder shares data between TheHive and APWG.

## Outline of Use

1. Set [Initial Responder Configuration](#Initial-Responder-Configuration)
2. As new observables arrive, appropriately [tag](#Tags-to-Modify-Responder-Behavior) them
3. Run the APWG responder
4. When complete, the indicator(s) should be submitted to APWG and the `apwg:submitted` tag will be added to 
the observable(s) in TheHive

## Initial Responder Configuration

The following need to be configured under **Organization --> Responders** prior to use:

`token` - **Required** - APWG token for API authentication

`confidence` - **Required** - Default indicator confidence (must be 50, 90, or 100; can be overriden by custom tags per observable)

`endpoint_phish` - **Required** - bool true/false whether to attempt to submit indicators to the APWG API /phish endpoint (URLs only)

`endpoint_mal_ip` - **Required** - bool true/false whether to attempt to submit indicators to the APWG API /mal_ip endpoint (IPs only)

`sandbox` - **Required** - bool true/false whether to submit indicators ONLY to the APWG sandbox API (default True for initial testing; changing to False will begin submitting to APWG production API)

## Tags to Modify Responder Behavior

Set any of the following tags to modify behavior of the created APWG indicator:

`apwg:confidence=90` - sets the APWG confidence_level of the indicator to 90 when submitting

`apwg:brand=Microsoft` - specifies the company or entity being targeted, in this case setting the brand of the indicator to "Microsoft" branded phishing

`apwg:desc=malicious ip` - gives a description for the /mal_ip endpoint, in this case setting the description of the indicator generically to "malicious ip"

`confidence:9` - a more generic confidence tag with values of 5, 9, or 10 is also considered; if present, the value is converted to 50, 90, or 100 respectively to meet the expectations of APWG's API. If no confidence tag is specified or the value is not one that APWG accepts, then the confidence is set to that of the confidence level specified in the [Initial Responder Configuration](#Initial-Responder-Configuration)