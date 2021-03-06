## Synopsis

The plan is to implement at least the *get* by key id or fingerprint operation of the [HKP protocol](https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00) in Google App Engine.  While implementing this, I came across the [Web Key Directory](https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-05) draft, so the ability to retrieve keys via this scheme was also added.  Note that this draft standard seems to be a moving target, and this code was written against draft 5.

## Code Example

Show what the library does as concisely as possible, developers should be able to figure out **how** your project solves their problem by looking at the code example. Make sure the API you are showing off is obvious, and that your code is short and concise.

## Motivation

I decided to make this when I saw that setting the *Preferred key server URL* in my public key in gpg to an absolute URL pointing to my key file did not work, and instead resulted in GPG trying to speak HKP to the server specified in the URL.

## Installation

Provide code examples and explanations of how to get the project.

## API Reference

Depending on the size of the project, if it is small and simple enough the reference docs can be added to the README. For medium size to larger projects it is important to at least provide a link to where the API reference docs live.

## Tests

Describe and show how to run the tests with code examples.

## Contributors

Let people know how they can dive into the project, include important links to things like issue trackers, irc, twitter accounts if applicable.

## License

A short snippet describing the license (MIT, Apache, etc.)
