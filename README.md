## Synopsis

A basic Java class for validating signed requests Facebook sends to your application (login with Facebook, Graph requests and so forth).

## Code Example

FacebookRequestValidator fbr = new FacebookRequestValidator();
boolean result = fbr.requestIsValid(signedRequest, your secret key);

## Motivation

Couldn't find anything quickly which did this so just created it.

## License

Do what you want.
