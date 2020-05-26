# CIFv3 Cortex Responder
Summary: Submits indicators to a CIFv3 instance from TheHive

Applies To: Case Observables (Artifacts), Alerts

Data sensitivity: This responder shares data between TheHive and a specified CIF instance.

## Outline of Use

1. Set [Initial Responder Configuration](#Initial-Responder-Configuration)
2. As new observables arrive, appropriately [tag](#Tags-to-Modify-Responder-Behavior) them
3. Run the CIFv3 responder
4. When complete, the indicator(s) should be created in the CIF instance and the `cifv3:submitted` tag will be added to 
the observable(s) in TheHive

## Initial Responder Configuration

The following need to be configured under **Organization --> Responders** prior to use:

`remote` - **Required** - CIF instance URL, e.g.: https://cif.domain.local:5000

`token` - **Required** - CIF token for API authentication

`verify_ssl` - **Required** - bool true/false whether to verify SSL on remote

`confidence` - **Required** - Default indicator confidence (can be overriden by custom tags per observable)

`group` - Group to assign newly created indicators in CIF (Default is `everyone`)

`tlp_map` - JSON object to map TheHive TLP to a custom value (Optional) 

Any tags on an observable without a colon (:) in them are added as tags to the submitted indicator. 
E.g., an indicator tagged in TheHive as `confidence:8`, `malware`, `threat` would be given `malware` and `threat` as CIF tags
upon submission as well as have its confidence set = 8.

## Tags to Modify Responder Behavior

Set any of the following tags to modify behavior of the created CIF indicator:

`confidence:7.5` - sets the CIF indicator confidence of that observable = 7.5
