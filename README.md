# @joph-auth/nd-aes-nodecrypto

`@joph-auth/nd-aes-nodecrypto` is a simple, no dependency, library for encrypting plaintext with 256 bit AES-GCM encryption
and PBKDF2 derived keys.

This package uses the [NodeJS crypto module](https://nodejs.org/api/crypto.html) 
and therefore can only be used in NodeJS where the crypto module is available.

For compatibility with the [web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), 
you should use `@joph-auth/nd-aes-webcrypto` instead.

**WARNING: This has been created solely for educational purposes and 
should not be used to encrypt sensitive data in real world applications.**

## Installing pre-built package

The package is published on npm and can be installed with

`npm install --save @joph-auth/nd-aes-nodecrypto`

or

`yarn add @joph-auth/nd-aes-nodecrypto`

The package contains 2 builds.
- `dist/lib-cjs` - Default - Built for CommonJS modules.
- `dist/lib-esm` - Built for ES2020 modules.

## Usage

### CommonJS
```javascript
const { encrypt, decrypt } = require('@joph-auth/nd-aes-nodecrypto');

async function example() {
  const cipher = await encrypt('plain text', 'password');
  console.log(cipher);

  const decrypted = await decrypt(cipher, 'password');
  console.log(decrypted);
}
```

### ES Modules
```javascript
import { encrypt, decrypt } from '@joph-auth/nd-aes-nodecrypto/dist/lib-esm';

async function example() {
  const cipher = await encrypt('plain text', 'password');
  console.log(cipher);

  const decrypted = await decrypt(cipher, 'password');
  console.log(decrypted);
}
```

### PBKDF2 iterations
It is possible to change the number of PBKDF2 iterations applied to the plaintext password.
The default is 10,000 iterations which is the minimum recommended by OWASP, however, this should be increased to the maximum possible whilst maintaining acceptable performance for your use case.

```javascript
async function example() {
    const cipher = await encrypt('plain text', 'password', 1000000);
    const decrypted = await decrypt(cipher, 'password', 1000000);
}
```

## Build from source
You can clone this repo and build manually.

Run `yarn` or `npm install` to install dev dependencies.

Scripts included in `package.json` are;
- `build:cjs` - Builds the library for CommonJS modules.
- `build:esm` - Builds the library for ES modules.
- `build` - Builds all of the above.
