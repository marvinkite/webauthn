WebAuthn Library
=============
[![GoDoc](https://godoc.org/github.com/teamhanko/webauthn?status.svg)](https://godoc.org/github.com/duo-labs/webauthn)
[![Go Report Card](https://goreportcard.com/badge/github.com/teamhanko/webauthn)](https://goreportcard.com/report/github.com/duo-labs/webauthn)


This library is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go apps that wish to implement a passwordless solution for users. 
This is the fork of [hanko.io](https://hanko.io) of the library originally written by [duo-labs](https://github.com/duo-labs/webauthn).
We modified it to suit our needs and added some missing features:

* Support for Resident Keys
* Possibility to add a Policy which decides on which Authenticators are accepted when an Attestation is sent
* Apple Attestation support

