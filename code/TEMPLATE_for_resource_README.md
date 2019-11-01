# README.md template for submissions

Please use the following README.md format for code/resource submissions. View this document Raw and copy/paste to grab the markdown formatting.

Analyzer and responder submissions should eventually get merged into the official repo, whereas webhooks, custom scripts, and other code contributions that don't belong in the TheHive-Project repo will remain as long-term resources in this repo.

### Resource name

The resource name should be descriptive, e.g. Cortex-Responder-Auto_mailer.

### Use case

Describe the operational purpose for this code. For example, considering the Cortex-Responder-Auto_mailer mentioned above, the Use Case may be:

> Use on a case observable to send an email containing case description to an address tagged on the observable.

### Brief description

Succinctly describe the:

- action(s) performed by the code,
- any necessary inputs (tags, fields, etc.), and
- character of the output data (if any)

For example the Cortex-Responder-Auto_mailer Brief Description may be:

> Uses Cortex configuration to send email based on a case observable. An observable must be tagged with `contact:user@domain.tld` with the appropriate address substituted. Once the email is successfully sent, the Responder automatically tags the observable with `automailer:completed`.

### Data sensitivity

Make note of any sensitivity considerations for processed data, especially if the code contacts another service (hosted, third-party, etc.).

### Local environment requirements

Environment variables, configuration files, &c; or, "none".

For example:

> Mail configuration must be set in `System->Responder->Configuration`

> Read API key for threat-enrichment SaaS must be set in `System->Responder->Configuration`

### License and/or permissions required

MIT, Mozilla, BSD, &c.

### How to run the code

Essentially, the --help information if not available directly at runtime, including any prereqs if code involves compiling binaries. For analyzers, and responders, this can be as easy as clicking the appropriate icons in the webUI.

### Known issues

Any known issues.

### Acknowledgements and credits

If the author wishes attribution and/or other credit(s) should be acknowledged.
